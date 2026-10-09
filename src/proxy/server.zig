//! Accepts agent connections and owns the proxy's shared state: sessions,
//! tunnels and listeners.
const std = @import("std");
const common = @import("common");
const netstack = @import("netstack.zig");
const tun = @import("tun.zig");
const Tunnel = @import("tunnel.zig").Tunnel;

const Allocator = std.mem.Allocator;
const Link = common.Link;
const proto = common.proto;
const relay = common.relay;
const sock = common.sock;
const log = std.log.scoped(.server);

pub const Session = struct {
    server: *Server,
    id: u32 = 0,
    link: *Link,
    remote: std.net.Address,
    hello: []u8,
    hostname: []const u8 = "?",
    user: []const u8 = "?",
    os: []const u8 = "?",
    arch: []const u8 = "?",
    version: []const u8 = "?",
    /// Stable, host-derived agent identity (survives reconnects).
    ident: []const u8 = "?",
    pid: []const u8 = "?",
    /// Agent's self-destruct deadline (Unix ms), if it has one.
    expire_ms: ?i64 = null,
    /// Upstream agent this session was relayed through (see `relay` command).
    via: ?u32 = null,
    /// Flows accepted by this agent's listeners, dialed on the proxy side.
    relay: relay.Table,
    /// Next id for TUN flows / pings (guarded by netstack.lock).
    next_flow_id: u32 = 1,

    fn parseHello(self: *Session) void {
        var lines = std.mem.tokenizeScalar(u8, self.hello, '\n');
        while (lines.next()) |line| {
            const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
            const key = line[0..eq];
            const value = line[eq + 1 ..];
            if (std.mem.eql(u8, key, "hostname")) self.hostname = value;
            if (std.mem.eql(u8, key, "user")) self.user = value;
            if (std.mem.eql(u8, key, "os")) self.os = value;
            if (std.mem.eql(u8, key, "arch")) self.arch = value;
            if (std.mem.eql(u8, key, "version")) self.version = value;
            if (std.mem.eql(u8, key, "id")) self.ident = value;
            if (std.mem.eql(u8, key, "pid")) self.pid = value;
            if (std.mem.eql(u8, key, "expire")) self.expire_ms = std.fmt.parseInt(i64, value, 10) catch null;
        }
    }
};

pub const Listener = struct {
    id: u32,
    session: *Session,
    transport: proto.Transport,
    bind: std.net.Address,
    target: std.net.Address,
    active: bool = false,
    is_relay: bool = false,
};

pub const Server = struct {
    gpa: Allocator,
    static: common.noise.KeyPair,
    psk: [32]u8,
    autostart: bool,
    listen_address: std.net.Address,
    default_iface: []const u8,
    default_localhost_net: tun.Cidr,
    /// Sent with every TCP connect request.
    dial_timeout_ms: u16 = proto.default_dial_timeout_ms,
    /// Max TCP dials in flight per tunnel; further SYNs wait in a queue.
    max_dials: u32 = 256,

    /// Guards everything below. Lock order: Server.mutex -> netstack.lock.
    mutex: std.Thread.Mutex = .{},
    sessions: std.ArrayList(*Session) = .empty,
    next_id: u32 = 1,
    tunnels: std.ArrayList(*Tunnel) = .empty,
    listeners: std.ArrayList(Listener) = .empty,
    next_listener_id: u32 = 1,
    /// Local port of a relay dial into our own listener -> upstream session id.
    relay_ports: std.AutoHashMapUnmanaged(u16, u32) = .empty,
    /// Handshakes in progress, total and per source address.
    handshakes: u32 = 0,
    handshakes_per_ip: std.AutoHashMapUnmanaged([16]u8, u8) = .empty,

    shutting_down: std.atomic.Value(bool) = .init(false),

    const max_handshakes = 64;
    const max_handshakes_per_ip = 8;

    pub fn listen(self: *Server) !void {
        const listener = try sock.listenTcp(self.listen_address, 128);
        (try std.Thread.spawn(.{}, acceptLoop, .{ self, listener })).detach();
    }

    /// Where relayed agents are sent: our own listener (0.0.0.0 -> loopback).
    pub fn relayTarget(self: *Server) std.net.Address {
        var a = self.listen_address;
        if (a.any.family == std.posix.AF.INET and a.in.sa.addr == 0) a = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, a.getPort());
        return a;
    }

    fn acceptLoop(self: *Server, listener_: std.net.Server) void {
        var listener = listener_;
        while (true) {
            const conn = listener.accept() catch |err| {
                log.err("accept failed: {s}", .{@errorName(err)});
                std.Thread.sleep(std.time.ns_per_s);
                continue;
            };
            if (!self.beginHandshake(conn.address)) {
                log.warn("too many handshakes in progress, dropping {f}", .{conn.address});
                conn.stream.close();
                continue;
            }
            const t = std.Thread.spawn(.{}, sessionMain, .{ self, conn }) catch {
                self.endHandshake(conn.address);
                conn.stream.close();
                continue;
            };
            t.detach();
        }
    }

    fn ipKey(a: std.net.Address) [16]u8 {
        var k = [_]u8{0} ** 16;
        if (a.any.family == std.posix.AF.INET6) k = a.in6.sa.addr else k[0..4].* = std.mem.asBytes(&a.in.sa.addr).*;
        return k;
    }

    /// Admits a new handshake unless the global or per-address limit is reached.
    fn beginHandshake(self: *Server, from: std.net.Address) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.handshakes >= max_handshakes) return false;
        const gop = self.handshakes_per_ip.getOrPut(self.gpa, ipKey(from)) catch return false;
        if (!gop.found_existing) gop.value_ptr.* = 0;
        if (gop.value_ptr.* >= max_handshakes_per_ip) return false;
        gop.value_ptr.* += 1;
        self.handshakes += 1;
        return true;
    }

    fn endHandshake(self: *Server, from: std.net.Address) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.handshakes -= 1;
        const key = ipKey(from);
        if (self.handshakes_per_ip.getPtr(key)) |n| {
            n.* -= 1;
            if (n.* == 0) _ = self.handshakes_per_ip.remove(key);
        }
    }

    fn sessionMain(self: *Server, conn: std.net.Server.Connection) void {
        var hello_buf: [common.link.max_hello_len]u8 = undefined;
        const hs_result = common.link.serverHandshake(self.gpa, conn.stream.handle, self.static, self.psk, &hello_buf);
        self.endHandshake(conn.address);
        const hs = hs_result catch |err| {
            switch (err) {
                error.AuthenticationFailed => log.warn("rejected agent {f}: wrong -secret (or an agent from a different zunnel version)", .{conn.address}),
                else => log.warn("handshake with {f} failed: {s}", .{ conn.address, @errorName(err) }),
            }
            conn.stream.close();
            return;
        };
        const s = self.gpa.create(Session) catch {
            hs.link.destroy();
            return;
        };
        s.* = .{
            .server = self,
            .link = hs.link,
            .remote = conn.address,
            .hello = self.gpa.dupe(u8, hs.hello) catch &.{},
            .relay = .init(self.gpa, hs.link),
        };
        s.relay.on_dialed = .{ .ctx = s, .func = onRelayDialed };
        s.parseHello();

        var attached: ?*Tunnel = null;
        var covered_buf: [64]u8 = undefined;
        var covered: ?[]const u8 = null;
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            s.id = self.next_id;
            self.next_id += 1;
            if (isLoopback(conn.address)) {
                if (self.relay_ports.fetchRemove(conn.address.getPort())) |kv| s.via = kv.value;
            }
            self.sessions.append(self.gpa, s) catch {};
            if (conn.address.any.family == std.posix.AF.INET) {
                const ip = std.mem.asBytes(&conn.address.in.sa.addr).*;
                for (self.tunnels.items) |t| if (t.routeCovering(ip, &covered_buf)) |r| {
                    covered = r;
                    break;
                };
            }
            if (self.autostart) {
                if (self.findTunnelLocked(self.default_iface)) |t| if (t.activeSession() == null) {
                    t.attach(s);
                    attached = t;
                };
            }
        }
        var via_buf: [32]u8 = undefined;
        const via = if (s.via) |v| std.fmt.bufPrint(&via_buf, " via agent #{d}", .{v}) catch "" else "";
        std.debug.print("\n[+] agent #{d} joined: {s}@{s} ({s}/{s}) from {f}{s}\n", .{ s.id, s.user, s.hostname, s.os, s.arch, s.remote, via });
        if (attached) |t| std.debug.print("[*] tunnel {s} now routes through agent #{d}\n", .{ t.name, s.id });
        if (covered) |r| std.debug.print("[!] warning: route {s} covers agent #{d}'s address; its link may break. Remove that route.\n", .{ r, s.id });

        while (true) {
            const frame = s.link.recvFrame() catch break;
            self.dispatch(s, frame);
        }
        s.link.close();

        // Unregister first so the console can no longer reference it, then tear down.
        var stopped: std.ArrayList([]const u8) = .empty;
        defer stopped.deinit(self.gpa);
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (self.sessions.items, 0..) |x, i| if (x == s) {
                _ = self.sessions.orderedRemove(i);
                break;
            };
            for (self.tunnels.items) |t| if (t.detach(s)) stopped.append(self.gpa, t.name) catch {};
            var i: usize = 0;
            while (i < self.listeners.items.len) {
                if (self.listeners.items[i].session == s) _ = self.listeners.orderedRemove(i) else i += 1;
            }
            for (stopped.items) |name| std.debug.print("\n[!] tunnel {s} stopped: its agent disconnected\n", .{name});
        }
        std.debug.print("\n[-] agent #{d} ({s}@{s}) left\n", .{ s.id, s.user, s.hostname });

        s.relay.shutdown();
        s.link.destroy();
        self.gpa.free(s.hello);
        self.gpa.destroy(s);
    }

    fn dispatch(self: *Server, s: *Session, frame: common.link.Frame) void {
        switch (frame.type) {
            .ping => s.link.send(.pong, frame.id, frame.payload) catch {},
            .pong => {},
            .listener_ok, .listener_fail => self.onListenerReply(s, frame),
            .accepted => self.onAccepted(s, frame),
            else => {
                if (frame.id & proto.agent_id_bit != 0) {
                    _ = s.relay.dispatch(frame);
                    return;
                }
                self.mutex.lock();
                defer self.mutex.unlock();
                netstack.lock.lock();
                defer netstack.lock.unlock();
                for (self.tunnels.items) |t| {
                    if (t.session == s and t.handleFrameLocked(frame)) return;
                }
            },
        }
    }

    fn onListenerReply(self: *Server, s: *Session, frame: common.link.Frame) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.listeners.items, 0..) |*l, i| {
            if (l.id != frame.id or l.session != s) continue;
            if (frame.type == .listener_ok) {
                l.active = true;
                std.debug.print("\n[*] listener #{d} active: agent #{d} {s} {f} -> {f}\n", .{ l.id, s.id, @tagName(l.transport), l.bind, l.target });
            } else {
                std.debug.print("\n[!] listener #{d} failed on agent #{d}: {s}\n", .{ l.id, s.id, frame.payload });
                _ = self.listeners.orderedRemove(i);
            }
            return;
        }
    }

    fn onAccepted(self: *Server, s: *Session, frame: common.link.Frame) void {
        const fail = [_]u8{@intFromEnum(proto.FailReason.other)};
        const acc = proto.Accepted.decode(frame.payload) catch return s.link.send(.connect_fail, frame.id, &fail) catch {};
        const l = blk: {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (self.listeners.items) |l| if (l.id == acc.listener_id and l.session == s) break :blk l;
            break :blk null;
        } orelse return s.link.send(.connect_fail, frame.id, &fail) catch {};
        s.relay.dial(frame.id, l.transport, l.target, 0);
    }

    fn onRelayDialed(ctx: *anyopaque, target: std.net.Address, h: sock.Handle) void {
        const s: *Session = @ptrCast(@alignCast(ctx));
        const self = s.server;
        if (!target.eql(self.relayTarget())) return;
        const local = sock.localAddress(h) orelse return;
        self.mutex.lock();
        defer self.mutex.unlock();
        self.relay_ports.put(self.gpa, local.getPort(), s.id) catch {};
    }

    // ------------------------------------------------------ console helpers

    /// Caller holds `mutex`.
    pub fn findSessionLocked(self: *Server, id: u32) ?*Session {
        for (self.sessions.items) |s| if (s.id == id) return s;
        return null;
    }

    /// Caller holds `mutex`.
    pub fn findTunnelLocked(self: *Server, name: []const u8) ?*Tunnel {
        for (self.tunnels.items) |t| if (std.mem.eql(u8, t.name, name)) return t;
        return null;
    }

    pub fn findTunnel(self: *Server, name: []const u8) ?*Tunnel {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.findTunnelLocked(name);
    }

    /// Creates and registers a tunnel interface.
    pub fn createTunnel(self: *Server, name: []const u8, localhost_net: tun.Cidr) !*Tunnel {
        const index = blk: {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.findTunnelLocked(name) != null) return error.AlreadyExists;
            var idx: u8 = 0;
            while (idx < 250) : (idx += 1) {
                for (self.tunnels.items) |t| {
                    if (t.index == idx) break;
                } else {
                    // Skip addresses another program (e.g. a second proxy) already uses.
                    if (!sock.isLocalAddress(tun.localAddress(idx))) break :blk idx;
                }
            }
            return error.TooManyTunnels;
        };
        const t = try Tunnel.create(self.gpa, name, index, localhost_net);
        self.mutex.lock();
        defer self.mutex.unlock();
        self.tunnels.append(self.gpa, t) catch {
            t.destroy();
            return error.OutOfMemory;
        };
        return t;
    }

    pub fn deleteTunnel(self: *Server, name: []const u8) !void {
        const t = blk: {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (self.tunnels.items, 0..) |t, i| if (std.mem.eql(u8, t.name, name)) {
                _ = self.tunnels.orderedRemove(i);
                break :blk t;
            };
            return error.NoSuchInterface;
        };
        t.destroy();
    }

    /// Removes every tunnel (routes, adapters, firewall rules) and disconnects
    /// all agents. Safe to call more than once and from any thread.
    pub fn shutdown(self: *Server) void {
        if (self.shutting_down.swap(true, .acq_rel)) return;
        var tunnels: std.ArrayList(*Tunnel) = .empty;
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            std.mem.swap(std.ArrayList(*Tunnel), &self.tunnels, &tunnels);
            for (self.sessions.items) |s| s.link.close();
        }
        for (tunnels.items) |t| {
            std.debug.print("removing interface {s}\n", .{t.name});
            t.destroy();
        }
        tunnels.deinit(self.gpa);
    }

    /// Returns a description of the first session whose link address lies in
    /// `cidr` (routing it into a tunnel would cut that agent off). Caller holds `mutex`.
    pub fn linkCoveredLocked(self: *Server, net: tun.Cidr, buf: []u8) ?[]const u8 {
        for (self.sessions.items) |s| {
            if (s.remote.any.family != std.posix.AF.INET) continue;
            const ip = std.mem.asBytes(&s.remote.in.sa.addr).*;
            if (net.contains(ip)) return std.fmt.bufPrint(buf, "agent #{d}'s link address {d}.{d}.{d}.{d}", .{ s.id, ip[0], ip[1], ip[2], ip[3] }) catch "an agent's link address";
        }
        return null;
    }

    /// Asks agent `session_id` to open a listener. Returns the listener id.
    pub fn addListener(self: *Server, session_id: u32, transport: proto.Transport, bind: std.net.Address, target: std.net.Address, is_relay: bool) !u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const s = self.findSessionLocked(session_id) orelse return error.NoSuchAgent;
        const id = self.next_listener_id;
        try self.listeners.append(self.gpa, .{ .id = id, .session = s, .transport = transport, .bind = bind, .target = target, .is_relay = is_relay });
        self.next_listener_id += 1;
        var storage: [16]u8 = undefined;
        var buf: [proto.Endpoint.max_len]u8 = undefined;
        const ep = proto.addressEndpoint(transport, bind, &storage);
        s.link.send(.listener_add, id, ep.encode(&buf)) catch {
            _ = self.listeners.pop();
            return error.AgentGone;
        };
        return id;
    }

    pub fn deleteListener(self: *Server, id: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.listeners.items, 0..) |l, i| if (l.id == id) {
            l.session.link.send(.listener_del, id, &.{}) catch {};
            _ = self.listeners.orderedRemove(i);
            return;
        };
        return error.NoSuchListener;
    }
};

fn isLoopback(a: std.net.Address) bool {
    return a.any.family == std.posix.AF.INET and std.mem.asBytes(&a.in.sa.addr)[0] == 127;
}
