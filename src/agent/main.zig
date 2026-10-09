//! zunnel-agent: runs on the remote host, connects back to the proxy and dials
//! TCP/UDP flows on its behalf. Needs no privileges.
const std = @import("std");
const builtin = @import("builtin");
const common = @import("common");

const proto = common.proto;
const sock = common.sock;
const keys = common.keys;
const relay = common.relay;
const Link = common.Link;
const Listener = @import("listener.zig").Listener;
const icmp = @import("icmp.zig");
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.agent);

const usage =
    \\usage: zunnel-agent -connect <host:port> (-pubkey <key> | -insecure) [options]
    \\
    \\  -connect <host:port>  proxy address
    \\  -pubkey <key>         expected proxy public key (base64, printed by the proxy)
    \\  -insecure             accept any proxy key (prints the fingerprint)
    \\  -secret <secret>      shared secret, must match the proxy's -secret
    \\  -retry                reconnect forever when the connection drops
    \\
;

const Options = struct {
    host: []const u8 = "",
    port: u16 = proto.default_port,
    pubkey: ?[32]u8 = null,
    insecure: bool = false,
    secret: []const u8 = "",
    retry: bool = false,
};

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print(fmt ++ "\n", args);
    std.process.exit(1);
}

fn parseArgs(args: []const [:0]u8) Options {
    var o: Options = .{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = std.mem.trimLeft(u8, args[i], "-");
        const needs_value = std.mem.eql(u8, a, "connect") or std.mem.eql(u8, a, "pubkey") or std.mem.eql(u8, a, "secret");
        const value: []const u8 = if (needs_value) blk: {
            i += 1;
            if (i >= args.len) fatal("missing value for -{s}", .{a});
            break :blk args[i];
        } else "";
        if (std.mem.eql(u8, a, "connect")) {
            const colon = std.mem.lastIndexOfScalar(u8, value, ':') orelse fatal("-connect expects host:port", .{});
            o.host = std.mem.trim(u8, value[0..colon], "[]");
            o.port = std.fmt.parseInt(u16, value[colon + 1 ..], 10) catch fatal("invalid port in -connect", .{});
        } else if (std.mem.eql(u8, a, "pubkey")) {
            o.pubkey = keys.decode(value) catch fatal("invalid -pubkey", .{});
        } else if (std.mem.eql(u8, a, "secret")) {
            o.secret = value;
        } else if (std.mem.eql(u8, a, "insecure")) {
            o.insecure = true;
        } else if (std.mem.eql(u8, a, "retry")) {
            o.retry = true;
        } else if (std.mem.eql(u8, a, "h") or std.mem.eql(u8, a, "help")) {
            std.debug.print("{s}", .{usage});
            std.process.exit(0);
        } else {
            fatal("unknown option '{s}'\n\n{s}", .{ args[i], usage });
        }
    }
    if (o.host.len == 0) fatal("{s}", .{usage});
    if (o.pubkey == null and !o.insecure) fatal("either -pubkey or -insecure is required", .{});
    return o;
}

pub fn main() !void {
    const gpa = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);
    const opts = parseArgs(args);

    const hello = try buildHello(gpa);
    defer gpa.free(hello);
    const psk = common.noise.pskFromSecret(opts.secret);

    var backoff_s: u64 = 1;
    while (true) {
        if (runSession(gpa, opts, psk, hello)) {
            backoff_s = 1;
        } else |err| {
            switch (err) {
                error.KeyMismatch => fatal("proxy public key does not match -pubkey", .{}),
                error.ProtocolMismatch => fatal("proxy speaks a different zunnel protocol version; use matching builds", .{}),
                error.AuthenticationFailed, error.EndOfStream => log.err("handshake rejected: wrong -secret, or mismatched zunnel versions", .{}),
                else => log.err("session failed: {s}", .{@errorName(err)}),
            }
        }
        if (!opts.retry) break;
        log.info("reconnecting in {d}s", .{backoff_s});
        std.Thread.sleep(backoff_s * std.time.ns_per_s);
        backoff_s = @min(backoff_s * 2, 30);
    }
}

fn envOr(gpa: Allocator, names: []const []const u8, fallback: []const u8) []const u8 {
    for (names) |n| {
        if (std.process.getEnvVarOwned(gpa, n)) |v| return v else |_| {}
    }
    return gpa.dupe(u8, fallback) catch fallback;
}

/// Plain `key=value` lines describing this host, shown in the proxy console.
fn buildHello(gpa: Allocator) ![]u8 {
    const hostname: []const u8 = if (builtin.os.tag == .windows)
        envOr(gpa, &.{"COMPUTERNAME"}, "unknown")
    else blk: {
        var host_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
        break :blk gpa.dupe(u8, std.posix.gethostname(&host_buf) catch "unknown") catch "unknown";
    };
    const user = envOr(gpa, &.{ "USER", "USERNAME", "LOGNAME" }, "unknown");
    return std.fmt.allocPrint(gpa, "version={s}\nhostname={s}\nuser={s}\nos={s}\narch={s}\n", .{
        common.version, hostname, user, @tagName(builtin.os.tag), @tagName(builtin.cpu.arch),
    });
}

fn runSession(gpa: Allocator, opts: Options, psk: [32]u8, hello: []const u8) !void {
    log.info("connecting to {s}:{d}", .{ opts.host, opts.port });
    const stream = try std.net.tcpConnectToHost(gpa, opts.host, opts.port);
    const res = common.link.clientHandshake(gpa, stream.handle, opts.pubkey, psk, hello) catch |err| {
        stream.close();
        return err;
    };
    if (opts.pubkey == null) {
        log.warn("insecure mode: proxy key is {s}", .{&keys.encode(res.server_key)});
    }
    log.info("connected, tunnel is up", .{});

    var session: Session = .{ .gpa = gpa, .link = res.link, .table = .init(gpa, res.link) };
    session.run();
    log.info("connection to proxy closed", .{});
}

const Session = struct {
    gpa: Allocator,
    link: *Link,
    table: relay.Table,
    /// Only touched by the dispatch thread.
    listeners: std.AutoHashMapUnmanaged(u32, *Listener) = .empty,
    icmp_inflight: std.atomic.Value(u32) = .init(0),

    const max_icmp_inflight = 32;

    fn run(self: *Session) void {
        while (true) {
            const frame = self.link.recvFrame() catch break;
            self.dispatch(frame) catch |err| {
                log.err("dispatch: {s}", .{@errorName(err)});
                break;
            };
        }
        self.link.close();

        var it = self.listeners.valueIterator();
        while (it.next()) |l| l.*.stop();
        self.listeners.deinit(self.gpa);
        // Waits until no flow or helper thread references the link.
        self.table.shutdown();
        self.link.destroy();
    }

    fn dispatch(self: *Session, frame: common.link.Frame) !void {
        switch (frame.type) {
            .ping => try self.link.send(.pong, frame.id, frame.payload),
            .connect => {
                const req = proto.ConnectRequest.decode(frame.payload) catch
                    return self.link.send(.connect_fail, frame.id, &.{@intFromEnum(proto.FailReason.other)});
                self.table.dial(frame.id, req.transport, targetAddress(req), req.timeout_ms);
            },
            .icmp_echo => self.icmpEcho(frame.id, frame.payload),
            .listener_add => self.addListener(frame.id, frame.payload),
            .listener_del => if (self.listeners.fetchRemove(frame.id)) |kv| kv.value.stop(),
            else => _ = self.table.dispatch(frame),
        }
    }

    fn addListener(self: *Session, id: u32, payload: []const u8) void {
        const fail = struct {
            fn f(s: *Session, lid: u32, msg: []const u8) void {
                s.link.send(.listener_fail, lid, msg[0..@min(msg.len, 200)]) catch {};
            }
        }.f;
        if (self.listeners.contains(id)) return fail(self, id, "duplicate listener id");
        const bind = proto.Endpoint.decode(payload) catch return fail(self, id, "invalid request");
        const l = Listener.start(self.gpa, &self.table, id, bind) catch |err| return fail(self, id, @errorName(err));
        self.listeners.put(self.gpa, id, l) catch {
            l.stop();
            return fail(self, id, "OutOfMemory");
        };
        log.info("listener {d}: {s} {f}", .{ id, @tagName(bind.transport), proto.endpointAddress(bind) });
        self.link.send(.listener_ok, id, &.{}) catch {};
    }

    fn icmpEcho(self: *Session, id: u32, payload: []const u8) void {
        const req = proto.IcmpEcho.decode(payload) catch return;
        if (self.icmp_inflight.fetchAdd(1, .monotonic) >= max_icmp_inflight) {
            _ = self.icmp_inflight.fetchSub(1, .monotonic);
            return self.link.send(.icmp_reply, id, &.{ 0, 0, 0 }) catch {};
        }
        self.table.retainLive();
        const t = std.Thread.spawn(.{ .stack_size = 128 * 1024 }, icmpWorker, .{ self, id, req }) catch {
            _ = self.icmp_inflight.fetchSub(1, .monotonic);
            self.table.releaseLive();
            return;
        };
        t.detach();
    }

    fn icmpWorker(self: *Session, id: u32, req: proto.IcmpEcho) void {
        defer self.table.releaseLive();
        defer _ = self.icmp_inflight.fetchSub(1, .monotonic);
        const res = icmp.echo(self.gpa, req.addr, req.timeout_ms);
        var out: [3]u8 = .{ @intFromBool(res.ok), 0, 0 };
        std.mem.writeInt(u16, out[1..3], res.rtt_ms, .big);
        self.link.send(.icmp_reply, id, &out) catch {};
    }
};

fn targetAddress(req: proto.ConnectRequest) std.net.Address {
    // 240.0.0.0/4 is the agent's own loopback (proxies also remap their -localhost-net).
    if (req.addr.len == 4 and req.addr[0] & 0xf0 == proto.magic_localhost_net[0])
        return std.net.Address.initIp4(.{ 127, 0, 0, 1 }, req.port);
    return proto.endpointAddress(req);
}
