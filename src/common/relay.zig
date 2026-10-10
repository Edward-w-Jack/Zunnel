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
    dialing: u32 = 0,
    live: u32 = 0,
    on_dialed: ?DialHook = null,
    stop_requested: bool = false,
    io_thread: ?std.Thread = null,

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
            while (it.next()) |fp| fp.*.abortLocked();
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
            .connect_fail, .reset => flow.abortLocked(),
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
                .open_dirs = if (transport == .tcp) 2 else 1,
            })) |flow| {
                self.dialing += 1;
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
            .open_dirs = 2,
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
            .open_dirs = 1,
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
    open_dirs: u8 = 0,
    aborted: bool = false,

    /// peer -> socket bytes not yet written.
    inbox: std.ArrayList(u8) = .empty,
    inbox_fin: bool = false,
    send_closed: bool = false,

    credit: u32 = proto.initial_window,
    unreported: u32 = 0,

    want_dial: bool = false,
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
            self.abortLocked();
        }
        if (notify) self.table.link.send(.reset, self.id, &.{}) catch {};
        self.table.reactor.wake();
    }

    pub fn detachListener(self: *Flow, idle: bool) void {
        self.abort(idle);
        self.release();
    }

    /// Caller holds Table.mutex.
    fn abortLocked(self: *Flow) void {
        self.aborted = true;
        if (self.owns_handle) if (self.handle) |h| sock.shutdown(h, .both);
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
            self.abortLocked();
            return;
        }
        self.inbox.appendSlice(self.table.gpa, data) catch self.abortLocked();
    }

    /// What the reactor should listen for right now. Caller holds Table.mutex.
    fn desiredInterest(self: *Flow) reactor_mod.Interest {
        if (self.aborted) return .{};
        return switch (self.state) {
            .connecting => .{ .write = true },
            .waiting => .{}, // not registered yet
            .open => switch (self.transport) {
                .tcp => .{
                    .read = self.credit > 0 and self.open_dirs > 0 and !self.send_closed_hack(),
                    .write = self.inbox.items.len > 0 or (self.inbox_fin and !self.send_closed),
                },
                .udp => .{ .read = true },
                else => .{},
            },
            .closed => .{},
        };
    }

    fn send_closed_hack(self: *Flow) bool {
        _ = self;
        return false;
    }

    /// Earliest deadline (ms from now) this flow cares about, or null.
    fn nextDeadline(self: *Flow, now: i64) ?i32 {
        if (self.aborted) return 0;
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
    while (true) {
        var timeout_ms: i32 = 500;
        {
            table.mutex.lock();
            defer table.mutex.unlock();
            cleanupClosed(table);
            if (table.stop_requested and table.flows.count() == 0) return;
            syncRegistrations(table, &timeout_ms);
        }
        const n = table.reactor.wait(&events, timeout_ms) catch 0;
        table.mutex.lock();
        for (events[0..n]) |ev| dispatchEvent(table, ev);
        tickTime(table);
        cleanupClosed(table);
        table.mutex.unlock();
    }
}

/// Caller holds Table.mutex.
fn cleanupClosed(table: *Table) void {
    var dead: std.ArrayList(*Flow) = .empty;
    defer dead.deinit(table.gpa);
    var it = table.flows.valueIterator();
    while (it.next()) |fp| {
        const f = fp.*;
        if (f.aborted and (f.transport == .udp or f.inbox.items.len == 0 or f.state == .closed or f.state == .connecting)) {
            dead.append(table.gpa, f) catch continue;
        }
    }
    for (dead.items) |f| f.finalize();
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
        if (flow.state == .closed or flow.aborted or flow.no_register) continue;
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
    if (flow.state == .closed) return;
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
                table.link.send(.connect_ok, flow.id, &.{}) catch {};
                if (table.on_dialed) |hook| hook.func(hook.ctx, flow.target, flow.handle.?);
                table.dialing -|= 1;
            }
        },
        .open => {
            if (ev.readable) tcpRead(table, flow);
            if (ev.writable) tcpWrite(table, flow);
            if (ev.hup and flow.inbox.items.len == 0 and !flow.send_closed) tcpWrite(table, flow);
        },
        else => {},
    }
}

fn tcpRead(table: *Table, flow: *Flow) void {
    const h = flow.handle orelse return;
    var buf: [proto.max_payload]u8 = undefined;
    while (flow.credit > 0 and !flow.aborted) {
        const max = @min(flow.credit, buf.len);
        const n = sock.recv(h, buf[0..max]) catch |err| switch (err) {
            error.Timeout => return,
            else => {
                flow.abortLocked();
                table.link.send(.reset, flow.id, &.{}) catch {};
                return;
            },
        };
        if (n == 0) {
            table.link.send(.fin, flow.id, &.{}) catch {};
            flow.open_dirs -|= 1;
            flow.credit = 0; // stop reading
            return;
        }
        flow.credit -= @intCast(n);
        table.link.send(.data, flow.id, buf[0..n]) catch {
            flow.abortLocked();
            return;
        };
    }
}

fn tcpWrite(table: *Table, flow: *Flow) void {
    const h = flow.handle orelse return;
    while (flow.inbox.items.len > 0 and !flow.aborted) {
        const n = sock.send(h, flow.inbox.items) catch {
            flow.abortLocked();
            table.link.send(.reset, flow.id, &.{}) catch {};
            return;
        };
        if (n == 0) break;
        if (n < flow.inbox.items.len) std.mem.copyForwards(u8, flow.inbox.items[0 .. flow.inbox.items.len - n], flow.inbox.items[n..]);
        flow.inbox.shrinkRetainingCapacity(flow.inbox.items.len - n);
        flow.unreported +|= @intCast(n);
    }
    if (flow.unreported >= window_batch or (flow.inbox.items.len == 0 and flow.unreported > 0)) {
        table.link.sendWindow(flow.id, flow.unreported) catch {};
        flow.unreported = 0;
    }
    if (flow.inbox_fin and flow.inbox.items.len == 0 and !flow.send_closed) {
        sock.shutdown(h, .send);
        flow.send_closed = true;
        flow.open_dirs -|= 1;
    }
    if (flow.open_dirs == 0) flow.abortLocked();
}

fn udpEvent(table: *Table, flow: *Flow, ev: reactor_mod.Event) void {
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
        table.link.sendDroppable(.data, flow.id, buf[0..n]) catch {
            flow.abortLocked();
            return;
        };
    }
}

fn tickTime(table: *Table) void {
    const now = clock.monotonicMs();
    var it = table.flows.valueIterator();
    while (it.next()) |fp| {
        const flow = fp.*;
        if (flow.aborted) continue;
        switch (flow.state) {
            .connecting => if (now - flow.created > flow.dial_timeout_ms) failDial(flow, .timeout),
            .open => if (flow.transport == .udp and !flow.no_register and now - flow.last_active > udp_idle_ms) flow.abortLocked(),
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
    posix.connect(h, &addr.any, addr.getOsSockLen()) catch |err| switch (err) {
        error.WouldBlock => {}, // normal
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
    flow.table.link.send(.connect_ok, flow.id, &.{}) catch {};
    flow.table.dialing -|= 1;
}

fn failDial(flow: *Flow, reason: proto.FailReason) void {
    flow.table.link.send(.connect_fail, flow.id, &.{@intFromEnum(reason)}) catch {};
    flow.table.dialing -|= 1;
    flow.abortLocked();
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
