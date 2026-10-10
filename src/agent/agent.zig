//! The agent core: connects to the proxy, serves sessions and reconnects.
//! It never exits the process or requires a console, so the same code backs
//! the command-line agent and (later) a DLL build.
const std = @import("std");
const builtin = @import("builtin");
const common = @import("common");
const identity = @import("identity.zig");
const Config = @import("config.zig").Config;

const proto = common.proto;
const keys = common.keys;
const relay = common.relay;
const Link = common.Link;
const Listener = @import("listener.zig").Listener;
const icmp = @import("icmp.zig");
const netinfo = @import("netinfo.zig");
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.agent);

/// When set, the agent logs nothing (embedders such as a DLL set this).
pub var quiet = false;

/// Why `run` returned.
pub const RunResult = enum {
    /// `stop` was set by the embedder.
    stopped,
    /// The proxy sent `kill`.
    killed,
    /// The `expire` deadline passed.
    expired,
    /// The proxy's public key did not match the configured one.
    key_mismatch,
    /// The proxy speaks another protocol version.
    protocol_mismatch,
    /// Not retrying, and the connection ended or could not be made.
    disconnected,
};

/// Runs the agent until it is stopped, killed or expires (or, without
/// `retry`, until the first session ends).
pub fn run(gpa: Allocator, cfg: Config, stop: *std.atomic.Value(bool)) RunResult {
    if (expired(cfg)) return .expired;
    const hello = buildHello(gpa, cfg) catch return .disconnected;
    defer gpa.free(hello);
    const psk = common.noise.pskFromSecret(cfg.secret);

    var backoff_s: u64 = 1;
    while (true) {
        if (stop.load(.acquire)) return .stopped;
        if (expired(cfg)) return .expired;
        if (runSession(gpa, cfg, psk, hello, stop)) |end| {
            switch (end) {
                .disconnected => backoff_s = 1,
                .killed => return .killed,
                .expired => return .expired,
                .stopped => return .stopped,
            }
        } else |err| switch (err) {
            error.KeyMismatch => return .key_mismatch,
            error.ProtocolMismatch => return .protocol_mismatch,
            error.AuthenticationFailed, error.EndOfStream => log.err("handshake rejected: wrong secret, or mismatched zunnel versions", .{}),
            else => log.err("session failed: {s}", .{@errorName(err)}),
        }
        if (!cfg.retry) return .disconnected;
        log.info("reconnecting in {d}s", .{backoff_s});
        if (!sleepUnlessStopped(backoff_s * std.time.ms_per_s, cfg, stop)) {
            return if (stop.load(.acquire)) .stopped else .expired;
        }
        backoff_s = @min(backoff_s * 2, 30);
    }
}

fn expired(cfg: Config) bool {
    const at = cfg.expire_at_ms orelse return false;
    return std.time.milliTimestamp() >= at;
}

/// Sleeps in short slices; returns false if stopped or expired meanwhile.
fn sleepUnlessStopped(ms: u64, cfg: Config, stop: *std.atomic.Value(bool)) bool {
    var left = ms;
    while (left > 0) {
        if (stop.load(.acquire) or expired(cfg)) return false;
        const step: u64 = @min(left, 200);
        std.Thread.sleep(step * std.time.ns_per_ms);
        left -= step;
    }
    return true;
}

fn envOr(gpa: Allocator, names: []const []const u8, fallback: []const u8) []const u8 {
    for (names) |n| {
        if (std.process.getEnvVarOwned(gpa, n)) |v| return v else |_| {}
    }
    return gpa.dupe(u8, fallback) catch fallback;
}

fn currentPid() u64 {
    return switch (builtin.os.tag) {
        .windows => std.os.windows.GetCurrentProcessId(),
        .linux => @intCast(std.os.linux.getpid()),
        else => @intCast(std.c.getpid()),
    };
}

/// Plain `key=value` lines describing this host, shown in the proxy console.
fn buildHello(gpa: Allocator, cfg: Config) ![]u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const hostname: []const u8 = if (builtin.os.tag == .windows)
        envOr(arena, &.{"COMPUTERNAME"}, "unknown")
    else blk: {
        var host_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
        break :blk arena.dupe(u8, std.posix.gethostname(&host_buf) catch "unknown") catch "unknown";
    };
    const user = envOr(arena, &.{ "USER", "USERNAME", "LOGNAME" }, "unknown");
    var mid_buf: [256]u8 = undefined;
    const derived = identity.derive(identity.machineId(&mid_buf), user);
    const id = cfg.id orelse &derived;

    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;
    try w.print("version={s}\nid={s}\nhostname={s}\nuser={s}\nos={s}\narch={s}\npid={d}\n", .{
        common.version, id, hostname, user, @tagName(builtin.os.tag), @tagName(builtin.cpu.arch), currentPid(),
    });
    if (cfg.expire_at_ms) |at| try w.print("expire={d}\n", .{at});
    return out.toOwnedSlice();
}

const SessionEnd = enum(u8) { disconnected, killed, expired, stopped };

fn runSession(gpa: Allocator, cfg: Config, psk: [32]u8, hello: []const u8, stop: *std.atomic.Value(bool)) !SessionEnd {
    log.info("connecting to {s}:{d}", .{ cfg.host, cfg.port });
    const tcp = try std.net.tcpConnectToHost(gpa, cfg.host, cfg.port);
    common.sock.setKeepAlive(tcp.handle);
    common.sock.setNoDelay(tcp.handle);
    const transport = common.stream.TcpStream.wrap(gpa, tcp.handle) catch |err| {
        tcp.close();
        return err;
    };
    const res = common.link.clientHandshake(gpa, transport, cfg.pubkey, psk, hello) catch |err| {
        transport.close();
        return err;
    };
    if (cfg.pubkey == null) log.warn("insecure mode: proxy key is {s}", .{&keys.encode(res.server_key)});
    log.info("connected, tunnel is up", .{});

    var session: Session = .{ .gpa = gpa, .link = res.link, .table = .init(gpa, res.link) };
    // Stop/expiry must also end a session that is blocked waiting for frames.
    const watchdog = std.Thread.spawn(.{ .stack_size = 64 * 1024 }, Session.watch, .{ &session, cfg, stop }) catch null;
    session.run();
    session.done.store(true, .release);
    // The watchdog may close the link until it has exited: free it only then.
    if (watchdog) |t| t.join();
    session.link.destroy();
    log.info("connection to proxy closed", .{});
    return session.end.load(.acquire);
}

const Session = struct {
    gpa: Allocator,
    link: *Link,
    table: relay.Table,
    /// Only touched by the dispatch thread.
    listeners: std.AutoHashMapUnmanaged(u32, *Listener) = .empty,
    icmp_inflight: std.atomic.Value(u32) = .init(0),
    /// Why the session ended; set by `finish`.
    end: std.atomic.Value(SessionEnd) = .init(.disconnected),
    done: std.atomic.Value(bool) = .init(false),

    const max_icmp_inflight = 32;

    /// Records why the session ends. The dispatch thread (kill) and the
    /// watchdog (stop, expiry) can race: the first reason wins.
    fn finish(self: *Session, why: SessionEnd) void {
        _ = self.end.cmpxchgStrong(.disconnected, why, .acq_rel, .acquire);
    }

    /// Serves frames until the link ends, then stops listeners and flows.
    /// The caller destroys the link once the watchdog has exited.
    fn run(self: *Session) void {
        while (true) {
            const frame = self.link.recvFrame() catch break;
            self.dispatch(frame) catch |err| {
                if (err != error.Killed) log.err("dispatch: {s}", .{@errorName(err)});
                break;
            };
        }
        self.link.close();

        var it = self.listeners.valueIterator();
        while (it.next()) |l| l.*.stop();
        self.listeners.deinit(self.gpa);
        // Waits until no flow or helper thread references the link.
        self.table.shutdown();
    }

    /// Ends the session when the embedder stops the agent or it expires.
    fn watch(self: *Session, cfg: Config, stop: *std.atomic.Value(bool)) void {
        while (!self.done.load(.acquire)) {
            if (stop.load(.acquire)) {
                self.finish(.stopped);
                self.link.close();
                return;
            }
            if (expired(cfg)) {
                log.info("agent expired, shutting down", .{});
                self.finish(.expired);
                self.link.close();
                return;
            }
            std.Thread.sleep(200 * std.time.ns_per_ms);
        }
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
            .info_request => self.sendInfo(frame.id),
            .kill => {
                log.info("killed by the proxy", .{});
                self.finish(.killed);
                return error.Killed;
            },
            else => _ = self.table.dispatch(frame),
        }
    }

    /// Answers the proxy's `ifconfig` with this host's interfaces.
    fn sendInfo(self: *Session, id: u32) void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        netinfo.write(self.gpa, &out.writer) catch {};
        var text = out.written();
        if (text.len > proto.max_payload) {
            // Cut at a line boundary and say so.
            const cut = std.mem.lastIndexOfScalar(u8, text[0 .. proto.max_payload - 32], '\n') orelse proto.max_payload - 32;
            text = text[0..cut];
        }
        self.link.send(.info_reply, id, text) catch {};
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

/// A minimal proxy for tests: accepts one agent, optionally kills it, then
/// serves until the agent hangs up.
const FakeProxy = struct {
    listener: *std.net.Server,
    key: common.noise.KeyPair,
    send_kill: bool,
    up: std.atomic.Value(bool) = .init(false),
    err: ?anyerror = null,

    fn serve(self: *FakeProxy) void {
        self.serveInner() catch |err| {
            self.err = err;
        };
        self.up.store(true, .release); // also on failure, so stopWhenUp ends
    }

    fn serveInner(self: *FakeProxy) !void {
        const conn = try self.listener.accept();
        var hello_buf: [common.link.max_hello_len]u8 = undefined;
        const psk = common.noise.pskFromSecret("s3cret");
        const transport = common.stream.TcpStream.wrap(std.testing.allocator, conn.stream.handle) catch |err| {
            conn.stream.close();
            return err;
        };
        const hs = common.link.serverHandshake(std.testing.allocator, transport, self.key, psk, &hello_buf) catch |err| {
            transport.close();
            return err;
        };
        defer hs.link.destroy();
        if (std.mem.indexOf(u8, hs.hello, "id=test-agent\n") == null) return error.UnexpectedHello;
        self.up.store(true, .release);
        if (self.send_kill) try hs.link.send(.kill, 0, &.{});
        while (true) _ = hs.link.recvFrame() catch break;
    }

    fn stopWhenUp(self: *FakeProxy, stop: *std.atomic.Value(bool)) void {
        while (!self.up.load(.acquire)) std.Thread.sleep(5 * std.time.ns_per_ms);
        stop.store(true, .release);
    }
};

test "run ends cleanly when the proxy kills the agent or the embedder stops it" {
    // std.testing.allocator fails the test if the link is leaked or freed twice.
    const key = common.noise.KeyPair.generate();
    var listener = try common.sock.listenTcp(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0), 4);
    defer listener.deinit();
    const cfg: Config = .{
        .host = "127.0.0.1",
        .port = listener.listen_address.getPort(),
        .pubkey = key.public_key,
        .insecure = false,
        .secret = "s3cret",
        .retry = false,
        .expire_at_ms = null,
        .id = "test-agent",
    };
    for ([_]RunResult{ .killed, .stopped }) |want| {
        var proxy: FakeProxy = .{ .listener = &listener, .key = key, .send_kill = want == .killed };
        const proxy_thread = try std.Thread.spawn(.{}, FakeProxy.serve, .{&proxy});
        var stop = std.atomic.Value(bool).init(false);
        const stopper = if (want == .stopped) try std.Thread.spawn(.{}, FakeProxy.stopWhenUp, .{ &proxy, &stop }) else null;
        const got = run(std.testing.allocator, cfg, &stop);
        if (stopper) |t| t.join();
        proxy_thread.join();
        if (proxy.err) |err| return err;
        try std.testing.expectEqual(want, got);
    }
}
