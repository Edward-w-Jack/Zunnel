//! Relays flows between an OS socket and the link, with per-flow credit-based
//! flow control. Used by the agent (dialed flows and its listeners) and by the
//! proxy (connections accepted by agent listeners, dialed on the proxy side).
//!
//! Flow kinds:
//!   - dialed:  the peer asked us to connect somewhere (`Table.dial`); we
//!              answer connect_ok / connect_fail.
//!   - adopted: we accepted a TCP connection (`Table.adoptTcp`) and announced
//!              it; relaying starts once the peer answers connect_ok.
//!   - UDP listener associations (`Table.adoptUdp`): datagrams are read by the
//!              listener and replies go out with sendto on its socket.
const std = @import("std");
const proto = @import("proto.zig");
const sock = @import("sock.zig");
const link_mod = @import("link.zig");

const Link = link_mod.Link;
const Frame = link_mod.Frame;
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.relay);

const thread_cfg: std.Thread.SpawnConfig = .{ .stack_size = 256 * 1024 };
pub const udp_idle_ms = 120 * std.time.ms_per_s;

/// Called after a successful outgoing TCP dial (used by the proxy to track relays).
pub const DialHook = struct {
    ctx: *anyopaque,
    func: *const fn (ctx: *anyopaque, target: std.net.Address, h: sock.Handle) void,
};

pub const Table = struct {
    gpa: Allocator,
    link: *Link,
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    flows: std.AutoHashMapUnmanaged(u32, *Flow) = .empty,
    /// Flows not yet freed plus other borrowers (they may still use `link`).
    live: usize = 0,
    next_id: u32 = 0,
    on_dialed: ?DialHook = null,

    pub fn init(gpa: Allocator, link: *Link) Table {
        return .{ .gpa = gpa, .link = link };
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

    /// Aborts every flow and waits until nothing references the link anymore.
    /// Listeners feeding `adoptUdp` flows must be stopped first.
    pub fn shutdown(self: *Table) void {
        var all: std.ArrayList(*Flow) = .empty;
        defer all.deinit(self.gpa);
        self.mutex.lock();
        var it = self.flows.valueIterator();
        while (it.next()) |f| {
            all.append(self.gpa, f.*) catch {
                f.*.abort(false); // best effort: threads still notice
                continue;
            };
            f.*.retain();
        }
        self.mutex.unlock();
        for (all.items) |f| {
            f.kill();
            f.release();
        }
        self.mutex.lock();
        while (self.live > 0) self.cond.wait(&self.mutex);
        self.flows.deinit(self.gpa);
        self.mutex.unlock();
    }

    /// Handles connect_ok/connect_fail/data/window/fin/reset for a flow in this
    /// table. Returns false if `frame.id` is unknown.
    pub fn dispatch(self: *Table, frame: Frame) bool {
        const flow = blk: {
            self.mutex.lock();
            defer self.mutex.unlock();
            const f = self.flows.get(frame.id) orelse return false;
            f.retain();
            break :blk f;
        };
        defer flow.release();
        switch (frame.type) {
            .connect_ok => flow.peerReady(),
            .connect_fail, .reset => flow.kill(),
            .data => flow.pushData(frame.payload),
            .window => if (frame.payload.len == 4) flow.addCredit(std.mem.readInt(u32, frame.payload[0..4], .big)),
            .fin => flow.pushFin(),
            else => {},
        }
        return true;
    }

    /// Allocates an id in the agent's half of the id space.
    pub fn allocId(self: *Table) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (true) {
            self.next_id = (self.next_id +% 1) | proto.agent_id_bit;
            if (!self.flows.contains(self.next_id)) return self.next_id;
        }
    }

    fn insert(self: *Table, flow: *Flow) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const gop = self.flows.getOrPut(self.gpa, flow.id) catch return false;
        if (gop.found_existing) return false;
        gop.value_ptr.* = flow;
        self.live += 1;
        return true;
    }

    fn newFlow(self: *Table, f: Flow) ?*Flow {
        const flow = self.gpa.create(Flow) catch return null;
        flow.* = f;
        if (!self.insert(flow)) {
            self.gpa.destroy(flow);
            return null;
        }
        return flow;
    }

    fn removeFlow(self: *Table, flow: *Flow) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.flows.get(flow.id)) |f| {
            if (f == flow) _ = self.flows.remove(flow.id);
        }
    }

    /// The peer asked us to open `target`; replies connect_ok / connect_fail.
    pub fn dial(self: *Table, id: u32, transport: proto.Transport, target: std.net.Address) void {
        if (transport != .tcp and transport != .udp) {
            self.link.send(.connect_fail, id, &.{@intFromEnum(proto.FailReason.other)}) catch {};
            return;
        }
        const flow = self.newFlow(.{
            .table = self,
            .id = id,
            .transport = transport,
            .target = target,
            .open_dirs = if (transport == .tcp) 2 else 1,
        }) orelse {
            self.link.send(.connect_fail, id, &.{@intFromEnum(proto.FailReason.other)}) catch {};
            return;
        };

        if (transport == .udp) {
            // Open the socket before handling the next frame: the first datagram
            // follows right behind the request.
            const h = sock.udpConnect(target) catch |err| return flow.fail(proto.FailReason.fromError(err));
            sock.setRecvTimeout(h, 1000);
            flow.touch();
            flow.handle = h;
            flow.state = .open;
            self.link.send(.connect_ok, id, &.{}) catch {};
        }
        flow.retain();
        const t = (if (transport == .tcp)
            std.Thread.spawn(thread_cfg, Flow.tcpDialMain, .{flow})
        else
            std.Thread.spawn(thread_cfg, Flow.udpMain, .{flow})) catch {
            flow.release();
            return flow.fail(.other);
        };
        t.detach();
    }

    /// Registers an accepted TCP connection (takes ownership of `h`). Relaying
    /// starts when the peer answers connect_ok. Returns the new flow id.
    pub fn adoptTcp(self: *Table, h: sock.Handle) ?u32 {
        const flow = self.newFlow(.{
            .table = self,
            .id = self.allocId(),
            .transport = .tcp,
            .target = undefined,
            .handle = h,
            .state = .waiting,
            .open_dirs = 2,
        }) orelse {
            sock.close(h);
            return null;
        };
        return flow.id;
    }

    /// Registers a UDP association on a listener socket (not owned). The
    /// returned flow carries an extra reference for the listener, which must
    /// eventually call `Flow.detachListener`.
    pub fn adoptUdp(self: *Table, listener: sock.Handle, peer: std.net.Address) ?*Flow {
        const flow = self.newFlow(.{
            .table = self,
            .id = self.allocId(),
            .transport = .udp,
            .target = peer,
            .handle = listener,
            .owns_handle = false,
            .udp_peer = peer,
            .state = .open,
            .open_dirs = 1,
        }) orelse return null;
        flow.touch();
        flow.retain();
        return flow;
    }
};

pub const Flow = struct {
    table: *Table,
    id: u32,
    transport: proto.Transport,
    target: std.net.Address,

    /// The table entry holds one reference; every thread working on the flow holds one.
    refs: std.atomic.Value(u32) = .init(1),
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    handle: ?sock.Handle = null,
    owns_handle: bool = true,
    /// UDP listener associations reply with sendto to this address.
    udp_peer: ?std.net.Address = null,
    state: enum { connecting, waiting, open } = .connecting,
    /// peer -> socket bytes not yet written.
    inbox: std.ArrayList(u8) = .empty,
    inbox_fin: bool = false,
    aborted: bool = false,
    removed: bool = false,
    /// Bytes we may still send to the peer (TCP flow control).
    credit: u32 = proto.initial_window,
    /// Directions still running; the flow is finished when this reaches 0.
    open_dirs: u8,
    last_active: std.atomic.Value(i64) = .init(0),

    pub fn retain(self: *Flow) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *Flow) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        if (self.owns_handle) if (self.handle) |h| sock.close(h);
        const table = self.table;
        self.inbox.deinit(table.gpa);
        table.gpa.destroy(self);
        table.releaseLive();
    }

    pub fn touch(self: *Flow) void {
        self.last_active.store(std.time.milliTimestamp(), .monotonic);
    }

    pub fn idleMs(self: *Flow) i64 {
        return std.time.milliTimestamp() - self.last_active.load(.monotonic);
    }

    pub fn isAborted(self: *Flow) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.aborted;
    }

    /// Removes the flow from the table (dropping the table's reference).
    fn unlink(self: *Flow) void {
        self.mutex.lock();
        const was_removed = self.removed;
        self.removed = true;
        self.mutex.unlock();
        if (was_removed) return;
        self.table.removeFlow(self);
        self.release();
    }

    fn fail(self: *Flow, reason: proto.FailReason) void {
        self.table.link.send(.connect_fail, self.id, &.{@intFromEnum(reason)}) catch {};
        self.unlink();
    }

    /// Aborts both directions. `notify` sends a reset to the peer.
    pub fn abort(self: *Flow, notify: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.aborted) return;
        self.aborted = true;
        if (self.owns_handle) if (self.handle) |h| sock.shutdown(h, .both);
        self.cond.broadcast();
        if (notify) self.table.link.send(.reset, self.id, &.{}) catch {};
    }

    /// Aborts without notifying the peer; also unlinks flows whose threads never started.
    fn kill(self: *Flow) void {
        self.abort(false);
        self.mutex.lock();
        const waiting = self.state == .waiting;
        self.mutex.unlock();
        if (waiting) self.unlink();
    }

    /// Called by a direction's owner when it is done.
    fn dirDone(self: *Flow) void {
        self.mutex.lock();
        self.open_dirs -= 1;
        const finished = self.open_dirs == 0;
        self.mutex.unlock();
        if (finished) self.unlink();
    }

    /// Ends a UDP listener association (`idle` sends a reset to the peer).
    pub fn detachListener(self: *Flow, idle: bool) void {
        self.abort(idle);
        self.dirDone();
        self.release();
    }

    fn pushData(self: *Flow, data: []const u8) void {
        if (self.transport == .udp) {
            self.touch();
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.aborted) return;
            const h = self.handle orelse return;
            if (self.udp_peer) |peer| sock.sendTo(h, data, peer) catch {} else _ = sock.send(h, data) catch {};
            return;
        }
        self.mutex.lock();
        if (self.aborted) return self.mutex.unlock();
        const overflow = self.inbox.items.len + data.len > 2 * proto.initial_window;
        const ok = !overflow and if (self.inbox.appendSlice(self.table.gpa, data)) true else |_| false;
        if (ok) self.cond.broadcast();
        self.mutex.unlock();
        // Peer ignored flow control (or we are out of memory): drop the flow.
        if (!ok) self.abort(true);
    }

    fn pushFin(self: *Flow) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.inbox_fin = true;
        self.cond.broadcast();
    }

    fn addCredit(self: *Flow, n: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.credit +|= n;
        self.cond.broadcast();
    }

    /// connect_ok for an adopted TCP flow: start relaying.
    fn peerReady(self: *Flow) void {
        self.mutex.lock();
        const was_waiting = self.state == .waiting and !self.aborted;
        if (was_waiting) self.state = .open;
        self.mutex.unlock();
        if (!was_waiting) return;

        self.retain();
        const reader = std.Thread.spawn(thread_cfg, tcpReaderMain, .{self}) catch {
            self.release();
            self.abort(true);
            self.dirDone(); // reader
            self.dirDone(); // writer
            return;
        };
        reader.detach();
        self.startWriter();
    }

    fn startWriter(self: *Flow) void {
        self.retain();
        const writer = std.Thread.spawn(thread_cfg, tcpWriter, .{self}) catch {
            self.release();
            self.abort(true);
            self.dirDone();
            return;
        };
        writer.detach();
    }

    // ------------------------------------------------------------------ TCP

    fn tcpDialMain(self: *Flow) void {
        defer self.release();
        const table = self.table;
        const stream = std.net.tcpConnectToAddress(self.target) catch |err| {
            log.debug("flow {x}: dial {f} failed: {s}", .{ self.id, self.target, @errorName(err) });
            return self.fail(proto.FailReason.fromError(err));
        };
        sock.setNoDelay(stream.handle);

        self.mutex.lock();
        self.handle = stream.handle;
        const aborted = self.aborted;
        if (!aborted) self.state = .open;
        self.mutex.unlock();
        if (aborted) return self.unlink();

        table.link.send(.connect_ok, self.id, &.{}) catch {
            self.abort(false);
            return self.unlink();
        };
        if (table.on_dialed) |hook| hook.func(hook.ctx, self.target, stream.handle);

        self.startWriter();
        self.readLoop();
    }

    fn tcpReaderMain(self: *Flow) void {
        defer self.release();
        self.readLoop();
    }

    /// socket -> peer, limited by the peer's credit.
    fn readLoop(self: *Flow) void {
        const link = self.table.link;
        const h = self.handle.?;
        var buf: [proto.max_payload]u8 = undefined;
        while (true) {
            self.mutex.lock();
            while (self.credit == 0 and !self.aborted) self.cond.wait(&self.mutex);
            const stop = self.aborted;
            const max = @min(self.credit, buf.len);
            self.mutex.unlock();
            if (stop) break;

            const n = sock.recv(h, buf[0..max]) catch {
                self.abort(true);
                break;
            };
            if (n == 0) {
                link.send(.fin, self.id, &.{}) catch {};
                break;
            }
            self.mutex.lock();
            self.credit -= @intCast(n);
            self.mutex.unlock();
            link.send(.data, self.id, buf[0..n]) catch {
                self.abort(false);
                break;
            };
        }
        self.dirDone();
    }

    /// peer -> socket; returns credit as data is written.
    fn tcpWriter(self: *Flow) void {
        defer self.release();
        const gpa = self.table.gpa;
        const h = self.handle.?;
        var pending: std.ArrayList(u8) = .empty;
        defer pending.deinit(gpa);

        while (true) {
            self.mutex.lock();
            while (self.inbox.items.len == 0 and !self.inbox_fin and !self.aborted) self.cond.wait(&self.mutex);
            if (self.aborted) {
                self.mutex.unlock();
                break;
            }
            if (self.inbox.items.len == 0) { // fin and fully drained
                self.mutex.unlock();
                sock.shutdown(h, .send);
                break;
            }
            std.mem.swap(std.ArrayList(u8), &self.inbox, &pending);
            self.mutex.unlock();

            sock.sendAll(h, pending.items) catch {
                self.abort(true);
                break;
            };
            self.table.link.sendWindow(self.id, @intCast(pending.items.len)) catch {
                self.abort(false);
                break;
            };
            pending.clearRetainingCapacity();
        }
        self.dirDone();
    }

    // ------------------------------------------------------------------ UDP

    fn udpMain(self: *Flow) void {
        defer self.release();
        const link = self.table.link;
        const h = self.handle.?;
        var buf: [proto.max_payload]u8 = undefined;
        while (true) {
            if (self.isAborted()) break;
            const n = sock.recv(h, &buf) catch |err| switch (err) {
                error.Timeout => {
                    if (self.idleMs() > udp_idle_ms) {
                        self.abort(true);
                        break;
                    }
                    continue;
                },
                // ICMP port unreachable etc. surface as errors on connected UDP sockets.
                else => continue,
            };
            self.touch();
            link.sendDroppable(.data, self.id, buf[0..n]) catch {
                self.abort(false);
                break;
            };
        }
        self.dirDone();
    }
};
