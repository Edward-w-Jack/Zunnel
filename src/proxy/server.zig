//! Accepts agent connections and owns the proxy's shared state: sessions,
//! tunnels and listeners.
const std = @import("std");
const common = @import("common");
const netstack = @import("netstack.zig");
const tun = @import("tun.zig");
const Tunnel = @import("tunnel.zig").Tunnel;
const ui = @import("ui.zig");

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
    /// When this session was established (Unix ms).
    joined_ms: i64 = 0,
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

/// A listener belongs to an agent identity, not a connection: it is
/// (re)started whenever an agent with that identity connects.
pub const Listener = struct {
    id: u32,
    /// Agent identity (owned).
    ident: []const u8,
    transport: proto.Transport,
    bind: std.net.Address,
    target: std.net.Address,
    /// The session currently running it; null while that agent is offline.
    session: ?*Session = null,
    /// The agent confirmed the listener is open.
    active: bool = false,
    is_relay: bool = false,
};

/// Interface `iface` follows the agent with identity `ident`: whenever that
/// agent connects, the interface is attached to it (if it is free).
pub const Binding = struct {
    iface: []const u8, // owned
    ident: []const u8, // owned
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
    /// Agents connect without a shared secret (warned about on every join).
    no_secret: bool = false,

    /// Guards everything below. Lock order: Server.mutex -> netstack.lock.
    mutex: std.Thread.Mutex = .{},
    sessions: std.ArrayList(*Session) = .empty,
    next_id: u32 = 1,
    tunnels: std.ArrayList(*Tunnel) = .empty,
    listeners: std.ArrayList(Listener) = .empty,
    next_listener_id: u32 = 1,
    bindings: std.ArrayList(Binding) = .empty,
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
            .joined_ms = std.time.milliTimestamp(),
        };
        s.relay.on_dialed = .{ .ctx = s, .func = onRelayDialed };
        s.parseHello();

        var attached: std.ArrayList([]const u8) = .empty;
        defer attached.deinit(self.gpa);
        var restarted: usize = 0;
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
            // -autostart: the default interface follows the first agent that joins.
            if (self.autostart and self.findBindingLocked(self.default_iface) == null) {
                self.setBindingLocked(self.default_iface, s.ident) catch {};
            }
            // Re-attach every interface bound to this agent's identity.
            for (self.bindings.items) |b| {
                if (!std.mem.eql(u8, b.ident, s.ident)) continue;
                const t = self.findTunnelLocked(b.iface) orelse continue;
                if (t.activeSession() != null) continue;
                t.attach(s);
                attached.append(self.gpa, t.name) catch {};
            }
            // Restart this identity's listeners.
            for (self.listeners.items) |*l| {
                if (l.session != null or !std.mem.eql(u8, l.ident, s.ident)) continue;
                if (startListenerLocked(l, s)) restarted += 1;
            }
        }
        var via_buf: [32]u8 = undefined;
        const via = if (s.via) |v| std.fmt.bufPrint(&via_buf, " via agent #{d}", .{v}) catch "" else "";
        ui.event("[+] agent #{d} joined: {s}@{s} ({s}/{s}) id {s} from {f}{s}", .{ s.id, s.user, s.hostname, s.os, s.arch, s.ident, s.remote, via });
        for (attached.items) |name| ui.event("[*] tunnel {s} now routes through agent #{d}", .{ name, s.id });
        if (restarted > 0) ui.event("[*] restarting {d} listener(s) on agent #{d}", .{ restarted, s.id });
        if (self.no_secret) ui.event("[!] warning: running with -no-secret; anyone with the public key can join", .{});
        if (covered) |r| ui.event("[!] warning: route {s} covers agent #{d}'s address; its link may break. Remove that route.", .{ r, s.id });

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
            // Listeners stay registered and restart when the agent comes back.
            for (self.listeners.items) |*l| if (l.session == s) {
                l.session = null;
                l.active = false;
            };
            for (stopped.items) |name| ui.event("[!] tunnel {s} stopped: its agent disconnected (re-attaches when it reconnects)", .{name});
        }
        ui.event("[-] agent #{d} ({s}@{s}) left", .{ s.id, s.user, s.hostname });

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
            .info_reply => self.onInfoReply(s, frame.payload),
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
        for (self.listeners.items) |*l| {
            if (l.id != frame.id or l.session != s) continue;
            if (frame.type == .listener_ok) {
                l.active = true;
                ui.event("[*] listener #{d} active: agent #{d} {s} {f} -> {f}", .{ l.id, s.id, @tagName(l.transport), l.bind, l.target });
            } else {
                // Keep the record: it is retried the next time the agent connects.
                ui.event("[!] listener #{d} failed on agent #{d}: {s} (retried on reconnect; 'listener del {d}' removes it)", .{ l.id, s.id, frame.payload, l.id });
                l.session = null;
                l.active = false;
            }
            return;
        }
    }

    /// Prints an agent's `ifconfig` answer, with routes the operator may want.
    fn onInfoReply(self: *Server, s: *Session, text: []const u8) void {
        var iface_buf: [32]u8 = undefined;
        const iface = blk: {
            self.mutex.lock();
            defer self.mutex.unlock();
            for (self.tunnels.items) |t| if (t.activeSession() == s) {
                const n = @min(t.name.len, iface_buf.len);
                @memcpy(iface_buf[0..n], t.name[0..n]);
                break :blk iface_buf[0..n];
            };
            break :blk "<iface>";
        };
        const uplink: ?[4]u8 = if (s.remote.any.family == std.posix.AF.INET) std.mem.asBytes(&s.remote.in.sa.addr).* else null;

        std.debug.print("\n[*] agent #{d} ({s}@{s}) interfaces:\n", .{ s.id, s.user, s.hostname });
        var suggestions: std.ArrayList(u8) = .empty;
        defer suggestions.deinit(self.gpa);
        var lines = std.mem.tokenizeScalar(u8, text, '\n');
        while (lines.next()) |line| {
            const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
            const key = line[0..eq];
            const value = line[eq + 1 ..];
            if (std.mem.eql(u8, key, "gateway")) {
                std.debug.print("      default gateway {s}\n", .{value});
                continue;
            }
            if (!std.mem.eql(u8, key, "iface")) {
                std.debug.print("      {s}\n", .{line});
                continue;
            }
            // "iface=<name with spaces> <addr>/<len> ..." - addresses contain '/'.
            var first_addr = value.len;
            var toks = std.mem.tokenizeScalar(u8, value, ' ');
            while (toks.next()) |tok| if (std.mem.indexOfScalar(u8, tok, '/') != null) {
                first_addr = @intFromPtr(tok.ptr) - @intFromPtr(value.ptr);
                break;
            };
            const name = std.mem.trim(u8, value[0..first_addr], " ");
            std.debug.print("  {s}\n", .{name});
            var addrs = std.mem.tokenizeScalar(u8, value[first_addr..], ' ');
            while (addrs.next()) |a| {
                std.debug.print("      {s}\n", .{a});
                const net = tun.Cidr.parse(a) catch continue; // IPv6 addresses are skipped here
                const ip = std.mem.toBytes(std.mem.nativeToBig(u32, net.net));
                if (net.mask == 0xffffffff or ip[0] == 127 or (ip[0] == 169 and ip[1] == 254)) continue;
                const is_uplink = if (uplink) |u| net.contains(u) else false;
                if (is_uplink) {
                    suggestions.print(self.gpa, "      {f}  (agent's link to the proxy; don't route)\n", .{net}) catch {};
                } else suggestions.print(self.gpa, "      route add {f} {s}\n", .{ net, iface }) catch {};
            }
        }
        if (suggestions.items.len > 0) std.debug.print("  networks this agent can reach:\n{s}", .{suggestions.items});
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
            ui.event("removing interface {s}", .{t.name});
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

    /// Asks `s` to open listener `l`. Caller holds `mutex`.
    fn startListenerLocked(l: *Listener, s: *Session) bool {
        var storage: [16]u8 = undefined;
        var buf: [proto.Endpoint.max_len]u8 = undefined;
        const ep = proto.addressEndpoint(l.transport, l.bind, &storage);
        s.link.send(.listener_add, l.id, ep.encode(&buf)) catch return false;
        l.session = s;
        l.active = false;
        return true;
    }

    pub const AddedListener = struct { id: u32, started_on: ?u32 };

    /// Registers a listener for agent identity `ident`. It starts right away
    /// on a connected agent with that identity, otherwise when one connects.
    pub fn addListener(self: *Server, ident: []const u8, transport: proto.Transport, bind: std.net.Address, target: std.net.Address, is_relay: bool) !AddedListener {
        self.mutex.lock();
        defer self.mutex.unlock();
        const owned = try self.gpa.dupe(u8, ident);
        errdefer self.gpa.free(owned);
        const id = self.next_listener_id;
        try self.listeners.append(self.gpa, .{ .id = id, .ident = owned, .transport = transport, .bind = bind, .target = target, .is_relay = is_relay });
        self.next_listener_id += 1;
        const l = &self.listeners.items[self.listeners.items.len - 1];
        for (self.sessions.items) |s| {
            if (!std.mem.eql(u8, s.ident, ident)) continue;
            if (startListenerLocked(l, s)) return .{ .id = id, .started_on = s.id };
        }
        return .{ .id = id, .started_on = null };
    }

    pub fn deleteListener(self: *Server, id: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.listeners.items, 0..) |l, i| if (l.id == id) {
            if (l.session) |s| s.link.send(.listener_del, id, &.{}) catch {};
            self.gpa.free(l.ident);
            _ = self.listeners.orderedRemove(i);
            return;
        };
        return error.NoSuchListener;
    }

    // ----------------------------------------------------------- bindings

    /// Caller holds `mutex`.
    pub fn findBindingLocked(self: *Server, iface: []const u8) ?*Binding {
        for (self.bindings.items) |*b| if (std.mem.eql(u8, b.iface, iface)) return b;
        return null;
    }

    /// Makes `iface` follow agent identity `ident` (replacing any previous
    /// binding). Caller holds `mutex`.
    pub fn setBindingLocked(self: *Server, iface: []const u8, ident: []const u8) !void {
        const new_ident = try self.gpa.dupe(u8, ident);
        if (self.findBindingLocked(iface)) |b| {
            self.gpa.free(b.ident);
            b.ident = new_ident;
            return;
        }
        errdefer self.gpa.free(new_ident);
        const new_iface = try self.gpa.dupe(u8, iface);
        errdefer self.gpa.free(new_iface);
        try self.bindings.append(self.gpa, .{ .iface = new_iface, .ident = new_ident });
    }

    /// Removes the binding of `iface`, if any. Caller holds `mutex`.
    pub fn removeBindingLocked(self: *Server, iface: []const u8) bool {
        for (self.bindings.items, 0..) |b, i| if (std.mem.eql(u8, b.iface, iface)) {
            self.gpa.free(b.iface);
            self.gpa.free(b.ident);
            _ = self.bindings.orderedRemove(i);
            return true;
        };
        return false;
    }

    /// Attaches `iface` to a connected agent with identity `ident`, if the
    /// interface exists and is idle. Returns that agent. Caller holds `mutex`.
    pub fn attachBoundLocked(self: *Server, iface: []const u8, ident: []const u8) ?*Session {
        const t = self.findTunnelLocked(iface) orelse return null;
        if (t.activeSession() != null) return null;
        for (self.sessions.items) |s| if (std.mem.eql(u8, s.ident, ident)) {
            t.attach(s);
            return s;
        };
        return null;
    }
};

fn isLoopback(a: std.net.Address) bool {
    return a.any.family == std.posix.AF.INET and std.mem.asBytes(&a.in.sa.addr)[0] == 127;
}
