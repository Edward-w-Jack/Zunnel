//! Relays flows between an OS socket and the link, with per-flow credit-based
//! flow control. One `Table` runs on a single I/O thread driven by `Reactor`:
//! sockets are non-blocking, state transitions react to readiness events, and
//! no thread is spawned per flow.
//!
//! Flow kinds:
//!   - dialed:  the peer asked us to connect somewhere (`Table.dial`); we
//!              answer connect_ok / connect_fail.
//!   - adopted: we accepted a TCP connection (`Table.adoptTcp`) and announced
//!              it; relaying starts once the peer answers connect_ok.
//!   - UDP listener associations (`Table.adoptUdp`): datagrams flow over a
//!              listener socket owned by someone else; the listener must call
//!              `Flow.detachListener` when it stops.
//!
//! A TCP flow ends cleanly once both directions are closed (the target's EOF
//! went to the peer as `fin`, and the peer's `fin` reached the target as a
//! send shutdown), or at once when either side resets. Either way the I/O
//! thread closes the socket on its next pass: a finished socket must not stay
//! registered, or poll() keeps reporting its hang-up and the thread spins.
//!
//! Threading: public `Table` and `Flow` methods are safe from any thread.
//! They hold the one `Table.mutex` while mutating state, then
//! `reactor.wake()` nudges the I/O thread to re-poll with the fresh view.
const std = @import("std");
const builtin = @import("builtin");
const clock = @import("clock.zig");
const proto = @import("proto.zig");
const sock = @import("sock.zig");
const link_mod = @import("link.zig");
const reactor_mod = @import("reactor.zig");

const posix = std.posix;
const is_windows = builtin.os.tag == .windows;
const Link = link_mod.Link;
const Frame = link_mod.Frame;
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.relay);

pub const udp_idle_ms = 120 * std.time.ms_per_s;
/// Max unsent bytes buffered per direction before we abort the flow for
/// ignoring our credit (TCP) or stop writing (UDP).
const inbox_cap: usize = 2 * proto.initial_window;
const default_dial_timeout_ms: u32 = proto.default_dial_timeout_ms;
/// Return flow-control credit to the peer in batches of at least this much.
const window_batch: u32 = 32 * 1024;

/// Called after a successful outgoing TCP dial (used by the proxy to track relays).
pub const DialHook = struct {
    ctx: *anyopaque,
    func: *const fn (ctx: *anyopaque, target: std.net.Address, h: sock.Handle) void,
};

pub const Table = struct {
    gpa: Allocator,
    link: *Link,
    reactor: reactor_mod.Reactor,
    /// Everything below is guarded by `mutex`.
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    flows: std.AutoHashMapUnmanaged(u32, *Flow) = .empty,
    next_id: u32 = 0,
    /// Dials in progress; each holds a slot until it connects or ends.
    dialing: u32 = 0,
    live: u32 = 0,
    on_dialed: ?DialHook = null,
    stop_requested: bool = false,
    io_thread: ?std.Thread = null,
    /// Scratch list for `cleanupClosed` (I/O thread only).
    dead: std.ArrayList(*Flow) = .empty,
    /// Passes through the I/O loop, so tests can check that it sleeps.
    loops: std.atomic.Value(u64) = .init(0),

    pub const max_concurrent_dials = 512;

    pub fn init(gpa: Allocator, link: *Link) !*Table {
        const t = try gpa.create(Table);
        errdefer gpa.destroy(t);
        t.* = .{ .gpa = gpa, .link = link, .reactor = undefined };
        t.reactor = try reactor_mod.Reactor.init(gpa);
        errdefer t.reactor.deinit();
        t.io_thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, ioMain, .{t});
        return t;
    }

    /// Lets a helper thread use `link` until `releaseLive`; shutdown waits for it.
    pub fn retainLive(self: *Table) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.live += 1;
    }

    pub fn releaseLive(self: *Table) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.live -= 1;
        self.cond.broadcast();
    }

    /// Signals all flows to abort, waits for the I/O thread, and frees the
    /// Table. Listeners feeding `adoptUdp` associations must be stopped first.
    pub fn shutdown(self: *Table) void {
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.stop_requested = true;
            var it = self.flows.valueIterator();
            while (it.next()) |fp| fp.*.abortLocked(false);
        }
        self.reactor.wake();
        if (self.io_thread) |t| {
            t.join();
            self.io_thread = null;
        }
        self.mutex.lock();
        while (self.live > 0) self.cond.wait(&self.mutex);
        self.mutex.unlock();
        self.reactor.deinit();
        self.dead.deinit(self.gpa);
        self.flows.deinit(self.gpa);
        self.gpa.destroy(self);
    }

    /// Handles a frame addressed to one of our flows. Returns false if the id
    /// isn't ours.
    pub fn dispatch(self: *Table, frame: Frame) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const flow = self.flows.get(frame.id) orelse return false;
        switch (frame.type) {
            .connect_ok => flow.onPeerReady(),
            .connect_fail, .reset => flow.abortLocked(false),
            .data => flow.pushData(frame.payload),
            .window => if (frame.payload.len == 4) {
                flow.credit +|= std.mem.readInt(u32, frame.payload[0..4], .big);
            },
            .fin => {
                flow.inbox_fin = true;
            },
            else => {},
        }
        self.reactor.wake();
        return true;
    }

    /// Agent-side id allocator (ids have `agent_id_bit` set).
    pub fn allocId(self: *Table) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.allocIdLocked();
    }

    fn allocIdLocked(self: *Table) u32 {
        while (true) {
            self.next_id = (self.next_id +% 1) | proto.agent_id_bit;
            if (self.next_id != 0 and !self.flows.contains(self.next_id)) return self.next_id;
        }
    }

    pub fn dial(self: *Table, id: u32, transport: proto.Transport, target: std.net.Address, timeout_ms: u16) void {
        if (transport != .tcp and transport != .udp) {
            self.link.send(.connect_fail, id, &.{@intFromEnum(proto.FailReason.other)}) catch {};
            return;
        }
        var post_fail = false;
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.dialing >= max_concurrent_dials) {
                post_fail = true;
            } else if (self.newFlowLocked(.{
                .table = self,
                .id = id,
                .transport = transport,
                .target = target,
                .state = .connecting,
                .dial_timeout_ms = if (timeout_ms == 0) default_dial_timeout_ms else timeout_ms,
                .created = clock.monotonicMs(),
                .last_active = clock.monotonicMs(),
            })) |flow| {
                self.dialing += 1;
                flow.holds_dial_slot = true;
                flow.want_dial = true;
                self.reactor.wake();
            } else {
                post_fail = true;
            }
        }
        if (post_fail) self.link.send(.connect_fail, id, &.{@intFromEnum(proto.FailReason.other)}) catch {};
    }

    pub fn adoptTcp(self: *Table, h: sock.Handle) ?u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        sock.setNonblocking(h) catch {
            sock.close(h);
            return null;
        };
        const id = self.allocIdLocked();
        _ = self.newFlowLocked(.{
            .table = self,
            .id = id,
            .transport = .tcp,
            .target = undefined,
            .handle = h,
            .state = .waiting,
            .last_active = clock.monotonicMs(),
        }) orelse {
            sock.close(h);
            return null;
        };
        self.reactor.wake();
        return id;
    }

    pub fn adoptUdp(self: *Table, listener: sock.Handle, peer: std.net.Address) ?*Flow {
        self.mutex.lock();
        defer self.mutex.unlock();
        const id = self.allocIdLocked();
        const flow = self.newFlowLocked(.{
            .table = self,
            .id = id,
            .transport = .udp,
            .target = peer,
            .handle = listener,
            .owns_handle = false,
            .udp_peer = peer,
            .state = .open,
            .last_active = clock.monotonicMs(),
        }) orelse return null;
        // Listener associations don't register the shared listener socket in
        // this reactor: the listener-owner polls it. Mark `no_register` so
        // the io thread doesn't try to add it.
        flow.no_register = true;
        flow.retain();
        return flow;
    }

    fn newFlowLocked(self: *Table, f: Flow) ?*Flow {
        const flow = self.gpa.create(Flow) catch return null;
        flow.* = f;
        const gop = self.flows.getOrPut(self.gpa, flow.id) catch {
            self.gpa.destroy(flow);
            return null;
        };
        if (gop.found_existing) {
            self.gpa.destroy(flow);
            return null;
        }
        gop.value_ptr.* = flow;
        return flow;
    }
};

pub const Flow = struct {
    table: *Table,
    id: u32,
    transport: proto.Transport,
    target: std.net.Address,

    refs: std.atomic.Value(u32) = .init(1),

    handle: ?sock.Handle = null,
    owns_handle: bool = true,
    /// UDP listener associations reply via sendto to this address.
    udp_peer: ?std.net.Address = null,
    /// Set when the socket is owned by someone else (a listener): the io
    /// thread must not add it to its reactor.
    no_register: bool = false,

    state: enum { connecting, waiting, open, closed } = .connecting,
    /// Reset by either side or failed locally: the I/O thread closes the
    /// socket on its next pass, whatever is still buffered.
    aborted: bool = false,
    /// Both TCP directions closed cleanly: closed like an aborted flow, but
    /// nobody needs to be told.
    done: bool = false,

    /// peer -> socket bytes not yet written.
    inbox: std.ArrayList(u8) = .empty,
    /// The peer sent `fin`: shut down our send side once `inbox` is written.
    inbox_fin: bool = false,
    /// Our send side is shut down (the peer's `fin` reached the target).
    tx_closed: bool = false,
    /// The target sent EOF and we passed it on as `fin`.
    rx_eof: bool = false,

    credit: u32 = proto.initial_window,
    unreported: u32 = 0,

    want_dial: bool = false,
    /// Counted in `Table.dialing` until the dial connects or the flow ends.
    holds_dial_slot: bool = false,
    registered: bool = false,

    created: i64 = 0,
    last_active: i64 = 0,
    dial_timeout_ms: u32 = default_dial_timeout_ms,

    pub fn retain(self: *Flow) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *Flow) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        const table = self.table;
        self.inbox.deinit(table.gpa);
        table.gpa.destroy(self);
    }

    pub fn touch(self: *Flow) void {
        self.table.mutex.lock();
        defer self.table.mutex.unlock();
        self.last_active = clock.monotonicMs();
    }

    pub fn idleMs(self: *Flow) i64 {
        self.table.mutex.lock();
        defer self.table.mutex.unlock();
        return clock.monotonicMs() - self.last_active;
    }

    pub fn isAborted(self: *Flow) bool {
        self.table.mutex.lock();
        defer self.table.mutex.unlock();
        return self.aborted;
    }

    pub fn abort(self: *Flow, notify: bool) void {
        {
            self.table.mutex.lock();
            defer self.table.mutex.unlock();
            self.abortLocked(notify);
        }
        self.table.reactor.wake();
    }

    pub fn detachListener(self: *Flow, idle: bool) void {
        self.abort(idle);
        self.release();
    }

    /// Caller holds Table.mutex. `notify` sends the peer a `reset`; pass
    /// false when the peer already knows (it reset us, or got connect_fail).
    /// The link only queues frames, so sending under the mutex is fine.
    fn abortLocked(self: *Flow, notify: bool) void {
        if (self.aborted) return;
        self.aborted = true;
        if (self.owns_handle) if (self.handle) |h| sock.shutdown(h, .both);
        if (notify) self.table.link.send(.reset, self.id, &.{}) catch {};
    }

    /// Caller holds Table.mutex. A TCP flow is finished once both directions
    /// are closed.
    fn checkDone(self: *Flow) void {
        if (self.rx_eof and self.tx_closed) self.done = true;
    }

    /// Caller holds Table.mutex.
    fn releaseDialSlot(self: *Flow) void {
        if (!self.holds_dial_slot) return;
        self.holds_dial_slot = false;
        self.table.dialing -= 1;
    }

    /// Peer answered connect_ok. Caller holds Table.mutex.
    fn onPeerReady(self: *Flow) void {
        if (self.state == .waiting) self.state = .open;
    }

    /// Peer sent bytes. Caller holds Table.mutex. UDP writes right away.
    fn pushData(self: *Flow, data: []const u8) void {
        if (self.aborted) return;
        if (self.transport == .udp) {
            self.last_active = clock.monotonicMs();
            const h = self.handle orelse return;
            if (self.udp_peer) |peer| sock.sendTo(h, data, peer) catch {} else _ = sock.send(h, data) catch {};
            return;
        }
        if (self.inbox.items.len + data.len > inbox_cap) {
            // The peer ignored our credit.
            self.abortLocked(true);
            return;
        }
        self.inbox.appendSlice(self.table.gpa, data) catch self.abortLocked(true);
    }

    /// What the reactor should listen for right now. Caller holds Table.mutex.
    fn desiredInterest(self: *Flow) reactor_mod.Interest {
        if (self.aborted or self.done) return .{};
        return switch (self.state) {
            .connecting => .{ .write = true },
            .waiting, .closed => .{},
            .open => switch (self.transport) {
                .tcp => .{
                    .read = !self.rx_eof and self.credit > 0,
                    .write = self.inbox.items.len > 0 or (self.inbox_fin and !self.tx_closed),
                },
                .udp => .{ .read = true },
                else => .{},
            },
        };
    }

    /// Earliest deadline (ms from now) this flow cares about, or null.
    fn nextDeadline(self: *Flow, now: i64) ?i32 {
        switch (self.state) {
            .connecting => return @intCast(@max(0, @as(i64, self.dial_timeout_ms) - (now - self.created))),
            .open => if (self.transport == .udp) return @intCast(@max(0, udp_idle_ms - (now - self.last_active))),
            else => {},
        }
        return null;
    }

    /// Caller holds Table.mutex. Removes the flow and drops the table's ref.
    fn finalize(self: *Flow) void {
        if (self.state == .closed) return;
        self.releaseDialSlot();
        self.state = .closed;
        if (self.registered) if (self.handle) |h| self.table.reactor.remove(h);
        self.registered = false;
        if (self.owns_handle) if (self.handle) |h| {
            sock.close(h);
            self.handle = null;
        };
        _ = self.table.flows.remove(self.id);
        self.release();
    }
};

// ------------------------------------------------------------- io thread

fn ioMain(table: *Table) void {
    var events: [128]reactor_mod.Event = undefined;
    var wait_failing = false;
    while (true) {
        var timeout_ms: i32 = 500;
        {
            table.mutex.lock();
            defer table.mutex.unlock();
            cleanupClosed(table);
            if (table.stop_requested and table.flows.count() == 0) return;
            syncRegistrations(table, &timeout_ms);
        }
        _ = table.loops.fetchAdd(1, .monotonic);
        const n = table.reactor.wait(&events, timeout_ms) catch |err| blk: {
            // Never spin on a failing poll.
            if (!wait_failing) log.err("reactor wait failed: {s}", .{@errorName(err)});
            wait_failing = true;
            std.Thread.sleep(10 * std.time.ns_per_ms);
            break :blk 0;
        };
        table.mutex.lock();
        for (events[0..n]) |ev| dispatchEvent(table, ev);
        tickTime(table);
        cleanupClosed(table);
        table.mutex.unlock();
    }
}

/// Caller holds Table.mutex. Drops every finished flow, whatever it still has
/// buffered: an aborted flow never writes again.
fn cleanupClosed(table: *Table) void {
    table.dead.clearRetainingCapacity();
    var it = table.flows.valueIterator();
    while (it.next()) |fp| {
        const f = fp.*;
        if (f.aborted or f.done) table.dead.append(table.gpa, f) catch break;
    }
    for (table.dead.items) |f| f.finalize();
}

fn syncRegistrations(table: *Table, timeout_ms: *i32) void {
    const now = clock.monotonicMs();
    var it = table.flows.valueIterator();
    while (it.next()) |fp| {
        const flow = fp.*;
        if (flow.want_dial and flow.state == .connecting) {
            flow.want_dial = false;
            startDial(flow);
        }
        if (flow.state == .closed or flow.aborted or flow.done or flow.no_register) continue;
        const h = flow.handle orelse continue;
        const interest = flow.desiredInterest();
        if (!flow.registered) {
            table.reactor.add(h, @ptrCast(flow), interest) catch continue;
            flow.registered = true;
        } else {
            table.reactor.modify(h, interest) catch {};
        }
        if (flow.nextDeadline(now)) |d| if (d < timeout_ms.*) {
            timeout_ms.* = @max(0, d);
        };
    }
}

fn dispatchEvent(table: *Table, ev: reactor_mod.Event) void {
    const flow: *Flow = @ptrCast(@alignCast(ev.ctx));
    if (flow.state == .closed or flow.aborted or flow.done) return;
    switch (flow.transport) {
        .tcp => tcpEvent(table, flow, ev),
        .udp => udpEvent(table, flow, ev),
        else => {},
    }
}

fn tcpEvent(table: *Table, flow: *Flow, ev: reactor_mod.Event) void {
    switch (flow.state) {
        .connecting => {
            if (ev.writable or ev.readable or ev.hup) {
                const code = sockError(flow.handle.?);
                if (code != 0 or ev.hup) return failDial(flow, mapSockErr(code));
                flow.state = .open;
                flow.last_active = clock.monotonicMs();
                flow.credit = proto.initial_window;
                flow.releaseDialSlot();
                table.link.send(.connect_ok, flow.id, &.{}) catch {};
                if (table.on_dialed) |hook| hook.func(hook.ctx, flow.target, flow.handle.?);
            }
        },
        .open => {
            if (ev.readable) tcpRead(table, flow);
            if (ev.writable and !flow.aborted) tcpWrite(table, flow);
        },
        else => {},
    }
}

fn tcpRead(table: *Table, flow: *Flow) void {
    const h = flow.handle orelse return;
    var buf: [proto.max_payload]u8 = undefined;
    while (!flow.rx_eof and flow.credit > 0) {
        const max = @min(flow.credit, buf.len);
        const n = sock.recv(h, buf[0..max]) catch |err| switch (err) {
            error.Timeout => return, // drained
            else => return flow.abortLocked(true),
        };
        if (n == 0) {
            // The target is done sending; pass that on once. The flow lives
            // on until our send side is closed too.
            flow.rx_eof = true;
            table.link.send(.fin, flow.id, &.{}) catch {};
            flow.checkDone();
            return;
        }
        flow.credit -= @intCast(n);
        table.link.send(.data, flow.id, buf[0..n]) catch return flow.abortLocked(false);
    }
}

fn tcpWrite(table: *Table, flow: *Flow) void {
    const h = flow.handle orelse return;
    while (flow.inbox.items.len > 0) {
        const n = sock.send(h, flow.inbox.items) catch |err| switch (err) {
            // The target reads slower than the peer sends: keep the rest and
            // wait for writability. Credit stays withheld meanwhile, so the
            // peer slows down instead of the connection being reset.
            error.WouldBlock => break,
            else => return flow.abortLocked(true),
        };
        if (n == 0) break;
        const rest = flow.inbox.items.len - n;
        if (rest > 0) std.mem.copyForwards(u8, flow.inbox.items[0..rest], flow.inbox.items[n..]);
        flow.inbox.shrinkRetainingCapacity(rest);
        flow.unreported +|= @intCast(n);
    }
    if (flow.unreported >= window_batch or (flow.inbox.items.len == 0 and flow.unreported > 0)) {
        table.link.sendWindow(flow.id, flow.unreported) catch {};
        flow.unreported = 0;
    }
    if (flow.inbox_fin and flow.inbox.items.len == 0 and !flow.tx_closed) {
        sock.shutdown(h, .send);
        flow.tx_closed = true;
        flow.checkDone();
    }
}

fn udpEvent(table: *Table, flow: *Flow, ev: reactor_mod.Event) void {
    // `readable` also covers a pending socket error (e.g. ICMP port
    // unreachable): the recv below returns it and clears it.
    if (!ev.readable) return;
    const h = flow.handle orelse return;
    var buf: [proto.max_payload]u8 = undefined;
    while (true) {
        const n = sock.recv(h, &buf) catch |err| switch (err) {
            error.Timeout => return,
            error.ConnectionReset => {
                table.link.send(.icmp_unreachable, flow.id, &.{3}) catch {};
                return;
            },
            else => return,
        };
        flow.last_active = clock.monotonicMs();
        table.link.sendDroppable(.data, flow.id, buf[0..n]) catch return flow.abortLocked(false);
    }
}

fn tickTime(table: *Table) void {
    const now = clock.monotonicMs();
    var it = table.flows.valueIterator();
    while (it.next()) |fp| {
        const flow = fp.*;
        if (flow.aborted or flow.done) continue;
        switch (flow.state) {
            .connecting => if (now - flow.created > flow.dial_timeout_ms) failDial(flow, .timeout),
            .open => if (flow.transport == .udp and !flow.no_register and now - flow.last_active > udp_idle_ms) flow.abortLocked(false),
            else => {},
        }
    }
}

fn startDial(flow: *Flow) void {
    switch (flow.transport) {
        .tcp => tcpStartConnect(flow),
        .udp => udpStartConnect(flow),
        else => failDial(flow, .other),
    }
}

fn tcpStartConnect(flow: *Flow) void {
    const addr = flow.target;
    const flags: u32 = if (is_windows) posix.SOCK.STREAM else posix.SOCK.STREAM | posix.SOCK.CLOEXEC;
    const h = posix.socket(addr.any.family, flags, posix.IPPROTO.TCP) catch |err| {
        return failDial(flow, proto.FailReason.fromError(err));
    };
    sock.setNonblocking(h) catch {
        sock.close(h);
        return failDial(flow, .other);
    };
    sock.connect(h, addr) catch |err| switch (err) {
        error.WouldBlock => {}, // in progress; the reactor reports the outcome
        else => {
            sock.close(h);
            return failDial(flow, proto.FailReason.fromError(err));
        },
    };
    flow.handle = h;
    flow.last_active = clock.monotonicMs();
}

fn udpStartConnect(flow: *Flow) void {
    const h = sock.udpConnect(flow.target) catch |err| return failDial(flow, proto.FailReason.fromError(err));
    sock.setNonblocking(h) catch {
        sock.close(h);
        return failDial(flow, .other);
    };
    flow.handle = h;
    flow.state = .open;
    flow.last_active = clock.monotonicMs();
    flow.releaseDialSlot();
    flow.table.link.send(.connect_ok, flow.id, &.{}) catch {};
}

fn failDial(flow: *Flow, reason: proto.FailReason) void {
    flow.table.link.send(.connect_fail, flow.id, &.{@intFromEnum(reason)}) catch {};
    flow.releaseDialSlot();
    flow.abortLocked(false);
}

fn sockError(h: sock.Handle) i32 {
    var code: i32 = 0;
    if (is_windows) {
        var len: i32 = @sizeOf(i32);
        _ = std.os.windows.ws2_32.getsockopt(h, std.os.windows.ws2_32.SOL.SOCKET, std.os.windows.ws2_32.SO.ERROR, std.mem.asBytes(&code), &len);
    } else {
        posix.getsockopt(h, posix.SOL.SOCKET, posix.SO.ERROR, std.mem.asBytes(&code)) catch {};
    }
    return code;
}

fn mapSockErr(code: i32) proto.FailReason {
    if (is_windows) {
        return switch (code) {
            10061 => .refused,
            10060 => .timeout,
            10051 => .unreachable_net,
            10065 => .unreachable_host,
            10013 => .prohibited,
            else => .other,
        };
    }
    return switch (@as(posix.E, @enumFromInt(code))) {
        .CONNREFUSED => .refused,
        .TIMEDOUT => .timeout,
        .NETUNREACH => .unreachable_net,
        .HOSTUNREACH => .unreachable_host,
        .ACCES, .PERM => .prohibited,
        else => .other,
    };
}

// --------------------------------------------------------------------- tests

const testing = std.testing;

/// A Table on one end of a link pair. The test plays the peer: it feeds
/// frames straight into `Table.dispatch` and reads what the Table sends from
/// the other end of the link.
const Harness = struct {
    table: *Table,
    link: *Link,
    peer: *Link,

    fn init() !Harness {
        const gpa = testing.allocator;
        const a, const b = try link_mod.testPair(gpa);
        errdefer {
            a.destroy();
            b.destroy();
        }
        // A frame that never comes fails the test instead of hanging it.
        b.stream.setRecvTimeout(5000);
        return .{ .table = try Table.init(gpa, a), .link = a, .peer = b };
    }

    fn deinit(h: *Harness) void {
        h.table.shutdown();
        h.link.destroy();
        h.peer.destroy();
    }

    fn feed(h: *Harness, ftype: proto.FrameType, id: u32, payload: []const u8) void {
        _ = h.table.dispatch(.{ .type = ftype, .id = id, .payload = payload });
    }

    fn feedWindow(h: *Harness, id: u32, credit: u32) void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, credit, .big);
        h.feed(.window, id, &b);
    }

    /// The next frame the Table sent, skipping heartbeats.
    fn next(h: *Harness) !Frame {
        while (true) {
            const f = try h.peer.recvFrame();
            if (f.type != .ping and f.type != .pong) return f;
        }
    }

    fn expectNext(h: *Harness, ftype: proto.FrameType, id: u32) !void {
        const f = try h.next();
        try testing.expectEqual(ftype, f.type);
        try testing.expectEqual(id, f.id);
    }

    /// Counts what the Table has sent for `id` so far: a marker queued behind
    /// it on the same link shows where "so far" ends.
    fn collect(h: *Harness, id: u32) !Seen {
        try h.link.send(.kill, 0, "marker");
        var seen: Seen = .{};
        while (true) {
            const f = try h.next();
            if (f.type == .kill and f.id == 0) return seen;
            if (f.id != id) continue;
            switch (f.type) {
                .fin => seen.fin += 1,
                .reset => seen.reset += 1,
                .data => seen.data += f.payload.len,
                else => {},
            }
        }
    }

    fn flowCount(h: *Harness) usize {
        h.table.mutex.lock();
        defer h.table.mutex.unlock();
        return h.table.flows.count();
    }

    /// Waits up to `ms` for the Table to hold exactly `want` flows.
    fn waitFlows(h: *Harness, want: usize, ms: i64) !void {
        const deadline = clock.monotonicMs() + ms;
        while (h.flowCount() != want) {
            if (clock.monotonicMs() > deadline) return error.TestTimeout;
            std.Thread.sleep(5 * std.time.ns_per_ms);
        }
    }

    /// With nothing to do, the I/O thread must sleep in poll (its timeout is
    /// 500 ms); a socket stuck in poll's ready set would make it spin.
    fn expectIdle(h: *Harness) !void {
        const before = h.table.loops.load(.monotonic);
        std.Thread.sleep(300 * std.time.ns_per_ms);
        const passes = h.table.loops.load(.monotonic) - before;
        if (passes > 20) {
            std.debug.print("I/O thread made {d} passes in 300 ms while idle\n", .{passes});
            return error.TestUnexpectedResult;
        }
    }
};

const Seen = struct {
    fin: u32 = 0,
    reset: u32 = 0,
    data: usize = 0,
};

/// A 127.0.0.1 listener standing in for the dial target.
fn listenLocal() !std.net.Server {
    return sock.listenTcp(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0), 8);
}

/// Shrinks the receive buffer of sockets accepted from listener `h` (set
/// before the handshake, so the advertised window starts small and the OS
/// doesn't auto-tune it).
fn setSmallRecvBuffer(h: sock.Handle) void {
    const size: i32 = 4096;
    if (is_windows) {
        const ws2 = std.os.windows.ws2_32;
        _ = ws2.setsockopt(h, ws2.SOL.SOCKET, ws2.SO.RCVBUF, std.mem.asBytes(&size), @sizeOf(i32));
    } else {
        posix.setsockopt(h, posix.SOL.SOCKET, posix.SO.RCVBUF, std.mem.asBytes(&size)) catch {};
    }
}

/// Accepts the Table's connection to `l`. Reads on it time out, so a missing
/// byte fails the test instead of hanging it.
fn acceptTarget(l: *std.net.Server) !sock.Handle {
    if (!sock.pollRead(l.stream.handle, 3000)) return error.TestTimeout;
    const conn = try l.accept();
    sock.setRecvTimeout(conn.stream.handle, 3000);
    return conn.stream.handle;
}

/// Reads `h` to EOF and expects exactly `want`.
fn expectReadToEof(h: sock.Handle, want: []const u8) !void {
    var buf: [1024]u8 = undefined;
    var got: usize = 0;
    while (got < buf.len) {
        const n = try sock.recv(h, buf[got..]);
        if (n == 0) break;
        got += n;
    }
    try testing.expectEqualStrings(want, buf[0..got]);
}

test "relay: client closes first: one fin, flow released, I/O thread idle" {
    var h = try Harness.init();
    defer h.deinit();
    var l = try listenLocal();
    defer l.deinit();

    h.table.dial(1, .tcp, l.listen_address, 2000);
    const target = try acceptTarget(&l);
    var target_open = true;
    defer if (target_open) sock.close(target);
    try h.expectNext(.connect_ok, 1);

    h.feed(.data, 1, "hello");
    h.feed(.fin, 1, &.{});
    try expectReadToEof(target, "hello");
    // The target closes after the client did: the agent sees EOF last.
    sock.close(target);
    target_open = false;

    try h.waitFlows(0, 2000);
    const seen = try h.collect(1);
    try testing.expectEqual(@as(u32, 1), seen.fin);
    try testing.expectEqual(@as(u32, 0), seen.reset);
    try h.expectIdle();
}

test "relay: target closes first: EOF passed on once, later upload still delivered" {
    var h = try Harness.init();
    defer h.deinit();
    var l = try listenLocal();
    defer l.deinit();

    h.table.dial(2, .tcp, l.listen_address, 2000);
    const target = try acceptTarget(&l);
    defer sock.close(target);
    try h.expectNext(.connect_ok, 2);

    try sock.sendAll(target, "response");
    sock.shutdown(target, .send);
    var got: [64]u8 = undefined;
    var got_len: usize = 0;
    while (true) {
        const f = try h.next();
        try testing.expectEqual(@as(u32, 2), f.id);
        switch (f.type) {
            .data => {
                @memcpy(got[got_len..][0..f.payload.len], f.payload);
                got_len += f.payload.len;
            },
            .fin => break,
            else => return error.TestUnexpectedResult,
        }
    }
    try testing.expectEqualStrings("response", got[0..got_len]);

    // Returning the credit must not make the Table read the EOF again.
    h.feedWindow(2, 8);
    h.feed(.data, 2, "upload");
    h.feed(.fin, 2, &.{});
    try expectReadToEof(target, "upload");
    try h.waitFlows(0, 2000);
    const seen = try h.collect(2);
    try testing.expectEqual(@as(u32, 0), seen.fin);
    try testing.expectEqual(@as(u32, 0), seen.reset);
    try h.expectIdle();
}

test "relay: a flow reset with data still buffered is released" {
    var h = try Harness.init();
    defer h.deinit();
    var l = try listenLocal();
    defer l.deinit();

    h.table.dial(3, .tcp, l.listen_address, 2000);
    const target = try acceptTarget(&l);
    defer sock.close(target);
    try h.expectNext(.connect_ok, 3);

    {
        // Under the mutex the I/O thread can't write the data out first.
        h.table.mutex.lock();
        defer h.table.mutex.unlock();
        const flow = h.table.flows.get(3).?;
        flow.pushData("never written");
        flow.abortLocked(false); // as if the peer's reset came right behind
        try testing.expect(flow.inbox.items.len > 0);
    }
    h.table.reactor.wake();
    try h.waitFlows(0, 2000);
    try h.expectIdle();
}

test "relay: UDP to a closed port reports unreachable and goes idle" {
    var h = try Harness.init();
    defer h.deinit();
    // A port nobody listens on: bind one, note it, close it.
    const probe = try sock.udpBind(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0));
    const closed = sock.localAddress(probe).?;
    sock.close(probe);

    h.table.dial(4, .udp, closed, 2000);
    try h.expectNext(.connect_ok, 4);
    h.feed(.data, 4, "anyone?");
    try h.expectNext(.icmp_unreachable, 4);
    try h.expectIdle();
}

/// Byte `i` of a test stream. Not periodic at 256, so a lost or repeated
/// chunk shows up.
fn patternByte(i: usize) u8 {
    return @truncate(i ^ (i >> 8) ^ (i >> 16));
}

/// Reads a target socket to EOF, but only after stalling long enough for
/// the socket buffers to fill.
const SlowReader = struct {
    handle: sock.Handle,
    got: usize = 0,
    bad: bool = false,

    fn run(self: *SlowReader) void {
        std.Thread.sleep(300 * std.time.ns_per_ms);
        var buf: [64 * 1024]u8 = undefined;
        while (true) {
            const n = sock.recv(self.handle, &buf) catch return;
            if (n == 0) return;
            for (buf[0..n], self.got..) |b, i| {
                if (b != patternByte(i)) self.bad = true;
            }
            self.got += n;
        }
    }
};

test "relay: a slow target gets everything, slowed by credit instead of reset" {
    var h = try Harness.init();
    defer h.deinit();
    var l = try listenLocal();
    defer l.deinit();
    setSmallRecvBuffer(l.stream.handle);

    h.table.dial(6, .tcp, l.listen_address, 2000);
    const target = try acceptTarget(&l);
    defer sock.close(target);
    try h.expectNext(.connect_ok, 6);

    var reader: SlowReader = .{ .handle = target };
    const t = try std.Thread.spawn(.{}, SlowReader.run, .{&reader});
    var joined = false;
    defer if (!joined) t.join(); // its reads time out after 3 s

    // Far more than the socket buffers hold while the target stalls. Like a
    // real peer, never send more than the credit the Table has granted.
    const total: usize = 8 * 1024 * 1024;
    var chunk: [32 * 1024]u8 = undefined;
    var credit: u64 = proto.initial_window;
    var sent: usize = 0;
    while (sent < total) {
        while (credit > 0 and sent < total) {
            const n: usize = @intCast(@min(chunk.len, credit, total - sent));
            for (chunk[0..n], sent..) |*b, i| b.* = patternByte(i);
            h.feed(.data, 6, chunk[0..n]);
            sent += n;
            credit -= n;
        }
        const f = try h.next();
        if (f.id != 6) continue;
        switch (f.type) {
            .window => credit += std.mem.readInt(u32, f.payload[0..4], .big),
            .reset => return error.TestUnexpectedResult,
            else => {},
        }
    }
    h.feed(.fin, 6, &.{});
    t.join();
    joined = true;
    try testing.expect(!reader.bad);
    try testing.expectEqual(total, reader.got);
}

test "relay: a pending dial that is reset gives its slot back" {
    var h = try Harness.init();
    defer h.deinit();
    // Unroutable, so the connect stays pending (or fails at once without a route).
    h.table.dial(5, .tcp, std.net.Address.initIp4(.{ 10, 255, 255, 1 }, 9), 3000);
    std.Thread.sleep(50 * std.time.ns_per_ms);
    h.feed(.reset, 5, &.{});
    try h.waitFlows(0, 2000);
    h.table.mutex.lock();
    defer h.table.mutex.unlock();
    try testing.expectEqual(@as(u32, 0), h.table.dialing);
}
