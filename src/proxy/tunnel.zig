//! One TUN interface routed through one agent session. Reads IP packets from
//! the TUN device, terminates TCP in the shared lwIP stack, and relays every
//! flow over the attached agent's link.
//!
//! TCP: a client SYN is held back until the agent reports that its own dial
//! succeeded; only then is the SYN handed to lwIP (which completes the
//! handshake). A failed dial is answered with RST, so port scans through the
//! tunnel see real open/closed results.
//!
//! UDP is handled without lwIP: datagrams are relayed as-is and replies are
//! re-wrapped into IP packets here. ICMP echo requests are forwarded to the
//! agent, which pings the host and reports whether it answered.
//!
//! Concurrency: `netstack.lock` serialises all lwIP calls and all flow state.
//! lwIP callbacks only ever run inside lwIP calls made while holding it.
const std = @import("std");
const common = @import("common");
const lwip = @import("lwip.zig");
const netstack = @import("netstack.zig");
const packet = @import("packet.zig");
const tun = @import("tun.zig");
const Session = @import("server.zig").Session;

const c = lwip.c;
const proto = common.proto;
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.tunnel);

const udp_idle_ms = 120 * std.time.ms_per_s;
const handshake_timeout_ms = 30 * std.time.ms_per_s;
const icmp_timeout_ms = 2000;
const max_pending_icmp = 256;
/// Return flow-control credit to the agent in batches of at least this much.
const window_batch = 32 * 1024;

// --------------------------------------------------------------------- types

const Tuple = struct {
    proto: u8,
    src: [4]u8,
    sport: u16,
    dst: [4]u8,
    dport: u16,
};

/// FIFO byte buffer.
const ByteQueue = struct {
    buf: std.ArrayList(u8) = .empty,
    head: usize = 0,

    fn len(q: *const ByteQueue) usize {
        return q.buf.items.len - q.head;
    }

    fn slice(q: *const ByteQueue) []const u8 {
        return q.buf.items[q.head..];
    }

    fn consume(q: *ByteQueue, n: usize) void {
        q.head += n;
        if (q.head == q.buf.items.len) {
            q.buf.clearRetainingCapacity();
            q.head = 0;
        }
    }

    /// Returns `n` writable bytes at the tail.
    fn reserve(q: *ByteQueue, gpa: Allocator, n: usize) ![]u8 {
        if (q.head > 0 and q.head >= q.buf.items.len / 2) {
            const live = q.len();
            std.mem.copyForwards(u8, q.buf.items[0..live], q.buf.items[q.head..]);
            q.buf.shrinkRetainingCapacity(live);
            q.head = 0;
        }
        return q.buf.addManyAsSlice(gpa, n);
    }

    fn deinit(q: *ByteQueue, gpa: Allocator) void {
        q.buf.deinit(gpa);
    }
};

const Flow = struct {
    tunnel: *Tunnel,
    id: u32,
    tuple: Tuple,
    state: enum { dialing, open } = .dialing,
    created: i64,

    // --- TCP
    /// The client's SYN, replayed into lwIP once the agent connected.
    syn: ?[]u8 = null,
    syn_seq: u32 = 0,
    pcb: ?*c.struct_tcp_pcb = null,
    /// client -> agent bytes waiting for agent credit (lwIP window stays closed meanwhile).
    from_client: ByteQueue = .{},
    credit: u32 = proto.initial_window,
    client_fin: bool = false,
    fin_sent: bool = false,
    /// agent -> client bytes not yet accepted by tcp_write.
    to_client: ByteQueue = .{},
    agent_fin: bool = false,
    shut_tx: bool = false,
    unreported: u32 = 0,

    // --- UDP
    last_active: i64 = 0,
};

/// An echo request waiting for the agent's verdict.
const PendingIcmp = struct {
    request: []u8,
    deadline: i64,
};

const Outcome = enum { alive, closed, aborted };

fn ip4Bytes(a: c.ip4_addr_t) [4]u8 {
    return std.mem.asBytes(&a.addr).*;
}

// -------------------------------------------------------------------- tunnel

pub const Tunnel = struct {
    gpa: Allocator,
    name: []const u8,
    /// Small unique number: picks the lwIP listener port and interface address.
    index: u8,
    dev: tun.Tun,
    /// Destinations in this network are dialed as 127.0.0.1 on the agent.
    localhost_net: tun.Cidr,
    /// Console-thread only.
    routes: std.ArrayList([]const u8) = .empty,
    running: std.atomic.Value(bool) = .init(true),
    reader: ?std.Thread = null,

    // Guarded by netstack.lock:
    session: ?*Session = null,
    netif: c.struct_netif = undefined,
    listener: ?*c.struct_tcp_pcb = null,
    flows: std.AutoHashMapUnmanaged(u32, *Flow) = .empty,
    by_tuple: std.AutoHashMapUnmanaged(Tuple, *Flow) = .empty,
    icmp: std.AutoHashMapUnmanaged(u32, PendingIcmp) = .empty,

    pub fn create(gpa: Allocator, if_name: []const u8, index: u8, localhost_net: tun.Cidr) !*Tunnel {
        try netstack.start(gpa);
        const self = try gpa.create(Tunnel);
        errdefer gpa.destroy(self);
        const owned_name = try gpa.dupe(u8, if_name);
        errdefer gpa.free(owned_name);
        self.* = .{
            .gpa = gpa,
            .name = owned_name,
            .index = index,
            .dev = try tun.Tun.open(gpa, if_name, index),
            .localhost_net = localhost_net,
        };
        errdefer self.dev.close();

        {
            netstack.lock.lock();
            defer netstack.lock.unlock();
            // The netif needs *an* address for lwIP to route output; with the
            // accept-all patch it never has to match real traffic.
            var addr: c.ip4_addr_t = .{ .addr = @bitCast(tun.localAddress(index)) };
            var mask: c.ip4_addr_t = .{ .addr = 0xffffffff };
            var gw: c.ip4_addr_t = .{ .addr = 0 };
            if (c.netif_add(&self.netif, &addr, &mask, &gw, self, netifInit, c.ip4_input) == null)
                return error.NetifAddFailed;
            errdefer c.netif_remove(&self.netif);
            if (c.netif_default == null) c.netif_set_default(&self.netif);
            c.netif_set_up(&self.netif);
            c.netif_set_link_up(&self.netif);

            // One wildcard listener per tunnel, bound to this netif so accepted
            // connections (and their SYN-ACKs) leave through the right TUN.
            const pcb = c.tcp_new() orelse return error.OutOfMemory;
            c.tcp_bind_netif(pcb, &self.netif);
            if (c.tcp_bind(pcb, null, 10000 + @as(u16, index)) != lwip.ERR_OK) {
                _ = c.tcp_close(pcb);
                return error.BindFailed;
            }
            const listener = c.tcp_listen_with_backlog(pcb, 255) orelse {
                _ = c.tcp_close(pcb);
                return error.ListenFailed;
            };
            c.tcp_arg(listener, self);
            c.tcp_accept(listener, onAccept);
            self.listener = listener;
            errdefer _ = c.tcp_close(listener);
            try netstack.register(self);
        }
        self.reader = try std.Thread.spawn(.{}, readerLoop, .{self});
        return self;
    }

    /// Tears the tunnel down. The caller must already have removed it from the
    /// server so no agent frames are routed to it anymore.
    pub fn destroy(self: *Tunnel) void {
        {
            netstack.lock.lock();
            defer netstack.lock.unlock();
            self.abortAll();
            self.session = null;
        }
        for (self.routes.items) |r| {
            self.dev.delRoute(r) catch {};
            self.gpa.free(r);
        }
        self.routes.deinit(self.gpa);
        self.running.store(false, .release);
        if (self.reader) |t| t.join();
        {
            netstack.lock.lock();
            defer netstack.lock.unlock();
            netstack.unregister(self);
            if (self.listener) |l| _ = c.tcp_close(l);
            c.netif_remove(&self.netif);
            var it = self.icmp.valueIterator();
            while (it.next()) |p| self.gpa.free(p.request);
            self.icmp.deinit(self.gpa);
            self.flows.deinit(self.gpa);
            self.by_tuple.deinit(self.gpa);
        }
        self.dev.close();
        self.gpa.free(self.name);
        self.gpa.destroy(self);
    }

    // ------------------------------------------------------------ control

    /// Routes all tunnel traffic through `session`, aborting flows of any previous agent.
    pub fn attach(self: *Tunnel, session: *Session) void {
        netstack.lock.lock();
        defer netstack.lock.unlock();
        if (self.session == session) return;
        self.abortAll();
        self.session = session;
    }

    /// Detaches `session` if it is the active one. Returns whether it was.
    pub fn detach(self: *Tunnel, session: *Session) bool {
        netstack.lock.lock();
        defer netstack.lock.unlock();
        if (self.session != session) return false;
        self.abortAll();
        self.session = null;
        return true;
    }

    pub fn activeSession(self: *Tunnel) ?*Session {
        netstack.lock.lock();
        defer netstack.lock.unlock();
        return self.session;
    }

    pub fn flowCount(self: *Tunnel) usize {
        netstack.lock.lock();
        defer netstack.lock.unlock();
        return self.flows.count();
    }

    pub fn addRoute(self: *Tunnel, cidr: []const u8) !void {
        for (self.routes.items) |r| if (std.mem.eql(u8, r, cidr)) return;
        try self.dev.addRoute(cidr);
        try self.routes.append(self.gpa, try self.gpa.dupe(u8, cidr));
    }

    pub fn delRoute(self: *Tunnel, cidr: []const u8) !void {
        for (self.routes.items, 0..) |r, i| {
            if (!std.mem.eql(u8, r, cidr)) continue;
            try self.dev.delRoute(cidr);
            self.gpa.free(self.routes.orderedRemove(i));
            return;
        }
        return error.NoSuchRoute;
    }

    fn abortAll(self: *Tunnel) void {
        while (true) {
            var it = self.flows.valueIterator();
            const flow = (it.next() orelse break).*;
            self.abortFlow(flow, true);
        }
        var it = self.icmp.valueIterator();
        while (it.next()) |p| self.gpa.free(p.request);
        self.icmp.clearRetainingCapacity();
    }

    // ------------------------------------------------------------ threads

    fn readerLoop(self: *Tunnel) void {
        var buf: [65536]u8 = undefined;
        while (self.running.load(.acquire)) {
            const n = self.dev.read(&buf) catch |err| {
                log.err("{s}: TUN read failed: {s}", .{ self.name, @errorName(err) });
                return;
            };
            if (n == 0) continue;
            netstack.lock.lock();
            defer netstack.lock.unlock();
            self.onPacket(buf[0..n]);
        }
    }

    /// Called by the netstack timer (lock held): expires idle UDP flows, TCP
    /// flows whose client never finished the handshake, and unanswered pings.
    pub fn sweepLocked(self: *Tunnel, now: i64) void {
        var stale: std.ArrayList(*Flow) = .empty;
        defer stale.deinit(self.gpa);
        var it = self.flows.valueIterator();
        while (it.next()) |fp| {
            const f = fp.*;
            const expired = if (f.tuple.proto == packet.proto_udp)
                now - f.last_active > udp_idle_ms
            else
                f.pcb == null and now - f.created > handshake_timeout_ms;
            if (expired) stale.append(self.gpa, f) catch break;
        }
        for (stale.items) |f| self.abortFlow(f, true);

        var expired_icmp: std.ArrayList(u32) = .empty;
        defer expired_icmp.deinit(self.gpa);
        var pit = self.icmp.iterator();
        while (pit.next()) |e| if (now > e.value_ptr.deadline) expired_icmp.append(self.gpa, e.key_ptr.*) catch break;
        for (expired_icmp.items) |id| if (self.icmp.fetchRemove(id)) |kv| self.gpa.free(kv.value.request);
    }

    // ------------------------------------------------------- packet input

    fn onPacket(self: *Tunnel, pkt: []const u8) void {
        const ip = packet.parseIp4(pkt) orelse return;
        switch (ip.proto) {
            packet.proto_tcp => {
                const seg = packet.parseTcp(ip.payload) orelse return;
                if (seg.flags & (packet.tcp_syn | packet.tcp_ack | packet.tcp_rst) == packet.tcp_syn) {
                    const t: Tuple = .{ .proto = packet.proto_tcp, .src = ip.src, .sport = seg.sport, .dst = ip.dst, .dport = seg.dport };
                    if (self.by_tuple.get(t)) |flow| {
                        if (flow.state == .dialing) return; // SYN retransmit while the agent dials
                    } else {
                        self.newTcpFlow(t, seg.seq, pkt);
                        return;
                    }
                }
                self.feed(pkt);
            },
            packet.proto_udp => self.onUdp(ip),
            packet.proto_icmp => self.onIcmp(ip, pkt),
            else => {},
        }
    }

    /// Hands a raw IPv4 packet to lwIP.
    fn feed(self: *Tunnel, pkt: []const u8) void {
        const p = c.pbuf_alloc(c.PBUF_RAW, @intCast(pkt.len), c.PBUF_RAM) orelse return;
        _ = c.pbuf_take(p, pkt.ptr, @intCast(pkt.len));
        if (self.netif.input.?(p, &self.netif) != lwip.ERR_OK) _ = c.pbuf_free(p);
    }

    /// Ids are allocated per session (shared by all of its tunnels).
    fn allocId(self: *Tunnel) u32 {
        const s = self.session.?;
        while (true) {
            const id = s.next_flow_id;
            s.next_flow_id = (s.next_flow_id +% 1) & ~proto.agent_id_bit;
            if (id != 0 and !self.flows.contains(id) and !self.icmp.contains(id)) return id;
        }
    }

    fn newFlow(self: *Tunnel, t: Tuple) !*Flow {
        const flow = try self.gpa.create(Flow);
        errdefer self.gpa.destroy(flow);
        flow.* = .{ .tunnel = self, .id = self.allocId(), .tuple = t, .created = std.time.milliTimestamp() };
        try self.flows.ensureUnusedCapacity(self.gpa, 1);
        try self.by_tuple.ensureUnusedCapacity(self.gpa, 1);
        self.flows.putAssumeCapacity(flow.id, flow);
        self.by_tuple.putAssumeCapacity(t, flow);
        return flow;
    }

    fn agentAddress(self: *Tunnel, dst: *const [4]u8) []const u8 {
        const loopback = [4]u8{ 127, 0, 0, 1 };
        return if (self.localhost_net.contains(dst.*)) &loopback else dst;
    }

    fn sendConnect(self: *Tunnel, flow: *Flow, transport: proto.Transport) !void {
        var buf: [proto.ConnectRequest.max_len]u8 = undefined;
        const req: proto.ConnectRequest = .{ .transport = transport, .addr = self.agentAddress(&flow.tuple.dst), .port = flow.tuple.dport };
        try self.session.?.link.send(.connect, flow.id, req.encode(&buf));
    }

    fn newTcpFlow(self: *Tunnel, t: Tuple, seq: u32, syn: []const u8) void {
        if (self.session == null) return self.sendRst(t, seq);
        const flow = self.newFlow(t) catch return;
        flow.syn_seq = seq;
        flow.syn = self.gpa.dupe(u8, syn) catch return self.abortFlow(flow, false);
        self.sendConnect(flow, .tcp) catch return self.abortFlow(flow, false);
    }

    fn sendRst(self: *Tunnel, t: Tuple, syn_seq: u32) void {
        var buf: [40]u8 = undefined;
        self.dev.write(packet.buildRst4(&buf, t.dst, t.dport, t.src, t.sport, syn_seq));
    }

    fn onUdp(self: *Tunnel, ip: packet.Ip4) void {
        const dgram = packet.parseUdp(ip.payload) orelse return;
        const session = self.session orelse return;
        if (ip.dst[0] >= 224 or std.mem.eql(u8, &ip.dst, &.{ 255, 255, 255, 255 })) return;
        if (dgram.data.len > proto.max_payload) return;
        const t: Tuple = .{ .proto = packet.proto_udp, .src = ip.src, .sport = dgram.sport, .dst = ip.dst, .dport = dgram.dport };
        const flow = self.by_tuple.get(t) orelse blk: {
            const f = self.newFlow(t) catch return;
            self.sendConnect(f, .udp) catch return self.abortFlow(f, false);
            break :blk f;
        };
        flow.last_active = std.time.milliTimestamp();
        session.link.sendDroppable(.data, flow.id, dgram.data) catch {};
    }

    fn onIcmp(self: *Tunnel, ip: packet.Ip4, pkt: []const u8) void {
        if (ip.payload.len < 8 or ip.payload[0] != packet.icmp_echo_request) return;
        if (self.localhost_net.contains(ip.dst)) return self.replyIcmp(ip);
        const session = self.session orelse return;
        if (self.icmp.count() >= max_pending_icmp) return;
        const id = self.allocId();
        const copy = self.gpa.dupe(u8, pkt) catch return;
        self.icmp.put(self.gpa, id, .{ .request = copy, .deadline = std.time.milliTimestamp() + icmp_timeout_ms + 1000 }) catch {
            self.gpa.free(copy);
            return;
        };
        const req: proto.IcmpEcho = .{ .addr = ip.dst, .timeout_ms = icmp_timeout_ms };
        session.link.send(.icmp_echo, id, &req.encode()) catch {};
    }

    fn replyIcmp(self: *Tunnel, req: packet.Ip4) void {
        var buf: [65536]u8 = undefined;
        if (packet.buildIcmpEchoReply4(&buf, req)) |reply| self.dev.write(reply);
    }

    // ------------------------------------------------------- agent frames

    /// Handles a frame for one of this tunnel's flows or pings. Caller holds
    /// netstack.lock and has checked that `self.session` sent it.
    pub fn handleFrameLocked(self: *Tunnel, frame: common.link.Frame) bool {
        if (frame.type == .icmp_reply) {
            const kv = self.icmp.fetchRemove(frame.id) orelse return false;
            defer self.gpa.free(kv.value.request);
            if (frame.payload.len >= 1 and frame.payload[0] == 1) {
                if (packet.parseIp4(kv.value.request)) |ip| self.replyIcmp(ip);
            }
            return true;
        }
        const flow = self.flows.get(frame.id) orelse return false;
        if (flow.tuple.proto == packet.proto_udp) {
            self.udpFrame(flow, frame);
            return true;
        }

        switch (frame.type) {
            .connect_ok => if (flow.state == .dialing) {
                flow.state = .open;
                if (flow.syn) |syn| {
                    flow.syn = null;
                    self.feed(syn);
                    self.gpa.free(syn);
                }
            },
            .connect_fail => {
                const reason: proto.FailReason = if (frame.payload.len > 0) @enumFromInt(frame.payload[0]) else .other;
                log.debug("dial {any}:{d} failed: {s}", .{ flow.tuple.dst, flow.tuple.dport, @tagName(reason) });
                self.abortFlow(flow, false);
            },
            .data => {
                if (flow.to_client.len() + frame.payload.len > 2 * proto.initial_window) {
                    self.abortFlow(flow, true); // agent ignored flow control
                    return true;
                }
                const dst = flow.to_client.reserve(self.gpa, frame.payload.len) catch {
                    self.abortFlow(flow, true);
                    return true;
                };
                @memcpy(dst, frame.payload);
                self.flushToClient(flow);
                _ = self.checkDone(flow);
            },
            .window => if (frame.payload.len == 4) {
                flow.credit +|= std.mem.readInt(u32, frame.payload[0..4], .big);
                self.flushToAgent(flow);
                _ = self.checkDone(flow);
            },
            .fin => {
                flow.agent_fin = true;
                self.flushToClient(flow);
                _ = self.checkDone(flow);
            },
            .reset => self.abortFlow(flow, false),
            else => {},
        }
        return true;
    }

    fn udpFrame(self: *Tunnel, flow: *Flow, frame: common.link.Frame) void {
        switch (frame.type) {
            .connect_ok => flow.state = .open,
            .connect_fail, .reset => self.destroyFlow(flow),
            .data => {
                flow.last_active = std.time.milliTimestamp();
                var buf: [tun.mtu + 64 + proto.max_payload]u8 = undefined;
                const t = flow.tuple;
                const pkt = packet.buildUdp4(&buf, t.dst, t.dport, t.src, t.sport, frame.payload) orelse return;
                self.dev.write(pkt);
            },
            else => {},
        }
    }

    // ----------------------------------------------------------- TCP relay

    /// client -> agent, limited by the agent's credit.
    fn flushToAgent(self: *Tunnel, flow: *Flow) void {
        const link = self.session.?.link;
        while (flow.from_client.len() > 0 and flow.credit > 0) {
            const n: u16 = @intCast(@min(flow.from_client.len(), flow.credit, proto.max_payload));
            link.send(.data, flow.id, flow.from_client.slice()[0..n]) catch {};
            flow.from_client.consume(n);
            flow.credit -= n;
            if (flow.pcb) |pcb| c.tcp_recved(pcb, n);
        }
        if (flow.client_fin and flow.from_client.len() == 0 and !flow.fin_sent) {
            link.send(.fin, flow.id, &.{}) catch {};
            flow.fin_sent = true;
        }
    }

    /// agent -> client, limited by lwIP's send buffer.
    fn flushToClient(self: *Tunnel, flow: *Flow) void {
        const pcb = flow.pcb orelse return;
        var wrote = false;
        while (flow.to_client.len() > 0) {
            const room: usize = pcb.snd_buf;
            const n = @min(room, flow.to_client.len(), 0xffff);
            if (n == 0) break;
            if (c.tcp_write(pcb, flow.to_client.slice().ptr, @intCast(n), c.TCP_WRITE_FLAG_COPY) != lwip.ERR_OK) break;
            flow.to_client.consume(n);
            flow.unreported += @intCast(n);
            wrote = true;
        }
        if (wrote) _ = c.tcp_output(pcb);

        if (flow.unreported >= window_batch or (flow.to_client.len() == 0 and flow.unreported > 0)) {
            self.session.?.link.sendWindow(flow.id, flow.unreported) catch {};
            flow.unreported = 0;
        }
        // Agent finished and everything is handed to lwIP: half-close towards the
        // client. If the client already closed, checkDone() closes the pcb fully.
        if (flow.agent_fin and flow.to_client.len() == 0 and !flow.client_fin and !flow.shut_tx) {
            _ = c.tcp_shutdown(pcb, 0, 1);
            flow.shut_tx = true;
        }
    }

    /// Closes the flow once both directions are finished.
    fn checkDone(self: *Tunnel, flow: *Flow) Outcome {
        const client_done = flow.client_fin and flow.fin_sent;
        const agent_done = flow.agent_fin and flow.to_client.len() == 0;
        if (!(client_done and agent_done)) return .alive;
        var outcome: Outcome = .closed;
        if (flow.pcb) |pcb| {
            detachPcb(pcb);
            if (c.tcp_close(pcb) != lwip.ERR_OK) {
                c.tcp_abort(pcb);
                outcome = .aborted;
            }
            flow.pcb = null;
        }
        self.destroyFlow(flow);
        return outcome;
    }

    /// Kills a flow immediately. Must not be called from inside an lwIP callback
    /// for the flow's own pcb.
    fn abortFlow(self: *Tunnel, flow: *Flow, notify_agent: bool) void {
        if (flow.pcb) |pcb| {
            detachPcb(pcb);
            c.tcp_abort(pcb);
            flow.pcb = null;
        } else if (flow.tuple.proto == packet.proto_tcp and flow.state == .dialing) {
            self.sendRst(flow.tuple, flow.syn_seq);
        }
        if (notify_agent) {
            if (self.session) |s| s.link.send(.reset, flow.id, &.{}) catch {};
        }
        self.destroyFlow(flow);
    }

    fn destroyFlow(self: *Tunnel, flow: *Flow) void {
        _ = self.flows.remove(flow.id);
        _ = self.by_tuple.remove(flow.tuple);
        if (flow.syn) |s| self.gpa.free(s);
        flow.from_client.deinit(self.gpa);
        flow.to_client.deinit(self.gpa);
        self.gpa.destroy(flow);
    }
};

fn detachPcb(pcb: *c.struct_tcp_pcb) void {
    c.tcp_arg(pcb, null);
    c.tcp_recv(pcb, null);
    c.tcp_sent(pcb, null);
    c.tcp_err(pcb, null);
}

// ------------------------------------------------------------ lwIP callbacks

fn netifInit(netif: ?*c.struct_netif) callconv(.c) c.err_t {
    const n = netif.?;
    n.name = .{ 'z', 'n' };
    n.mtu = tun.mtu;
    n.output = netifOutput;
    return lwip.ERR_OK;
}

fn netifOutput(netif: ?*c.struct_netif, p: ?*c.struct_pbuf, _: ?*const c.ip4_addr_t) callconv(.c) c.err_t {
    const self: *Tunnel = @ptrCast(@alignCast(netif.?.state.?));
    const q = p.?;
    var buf: [65536]u8 = undefined;
    const n = c.pbuf_copy_partial(q, &buf, q.tot_len, 0);
    self.dev.write(buf[0..n]);
    return lwip.ERR_OK;
}

fn onAccept(arg: ?*anyopaque, newpcb: ?*c.struct_tcp_pcb, err: c.err_t) callconv(.c) c.err_t {
    const pcb = newpcb orelse return lwip.ERR_OK;
    if (err != lwip.ERR_OK) return lwip.ERR_OK;
    const self: *Tunnel = @ptrCast(@alignCast(arg.?));
    const t: Tuple = .{
        .proto = packet.proto_tcp,
        .src = ip4Bytes(pcb.remote_ip),
        .sport = pcb.remote_port,
        .dst = ip4Bytes(pcb.local_ip),
        .dport = pcb.local_port,
    };
    const flow = self.by_tuple.get(t) orelse {
        c.tcp_abort(pcb);
        return lwip.ERR_ABRT;
    };
    if (flow.pcb != null or flow.state != .open) {
        c.tcp_abort(pcb);
        return lwip.ERR_ABRT;
    }
    flow.pcb = pcb;
    c.tcp_arg(pcb, flow);
    c.tcp_recv(pcb, onRecv);
    c.tcp_sent(pcb, onSent);
    c.tcp_err(pcb, onErr);
    pcb.flags |= c.TF_NODELAY;
    // The agent may already have sent data (e.g. an SSH banner).
    self.flushToClient(flow);
    return if (self.checkDone(flow) == .aborted) lwip.ERR_ABRT else lwip.ERR_OK;
}

fn onRecv(arg: ?*anyopaque, _: ?*c.struct_tcp_pcb, p: ?*c.struct_pbuf, _: c.err_t) callconv(.c) c.err_t {
    const flow: *Flow = @ptrCast(@alignCast(arg orelse {
        if (p) |q| _ = c.pbuf_free(q);
        return lwip.ERR_OK;
    }));
    const self = flow.tunnel;
    if (p) |q| {
        // On ERR_MEM lwIP keeps ownership of the pbuf and redelivers it later.
        const dst = flow.from_client.reserve(self.gpa, q.tot_len) catch return lwip.ERR_MEM;
        _ = c.pbuf_copy_partial(q, dst.ptr, q.tot_len, 0);
        _ = c.pbuf_free(q);
    } else {
        flow.client_fin = true;
    }
    self.flushToAgent(flow);
    return if (self.checkDone(flow) == .aborted) lwip.ERR_ABRT else lwip.ERR_OK;
}

fn onSent(arg: ?*anyopaque, _: ?*c.struct_tcp_pcb, _: u16) callconv(.c) c.err_t {
    const flow: *Flow = @ptrCast(@alignCast(arg orelse return lwip.ERR_OK));
    const self = flow.tunnel;
    self.flushToClient(flow);
    return if (self.checkDone(flow) == .aborted) lwip.ERR_ABRT else lwip.ERR_OK;
}

/// lwIP already freed the pcb (reset by the client, retransmit timeout...).
fn onErr(arg: ?*anyopaque, _: c.err_t) callconv(.c) void {
    const flow: *Flow = @ptrCast(@alignCast(arg orelse return));
    flow.pcb = null;
    flow.tunnel.abortFlow(flow, true);
}
