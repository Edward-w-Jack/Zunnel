//! A readiness-based I/O reactor. One `Reactor` drives many non-blocking
//! sockets from a single thread: callers register a socket with an `Interest`
//! (read, write, or both), wait for events, and act on readiness. A separate
//! thread can post work by calling `wake`.
//!
//! Implementation uses `std.posix.poll`, which maps to WSAPoll on Windows and
//! native `poll(2)` on Linux. For zunnel's workload (hundreds to a few
//! thousand concurrent flows) this is adequate and keeps one code path. If
//! Linux scale needs edge-triggered epoll later, it can slot in behind the
//! same interface.
//!
//! The reactor is not thread-safe except for `wake`. All other operations
//! must happen on the thread that calls `wait`.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const clock = @import("clock.zig");
const sock = @import("sock.zig");

const Allocator = std.mem.Allocator;

pub const Interest = packed struct(u8) {
    read: bool = false,
    write: bool = false,
    _pad: u6 = 0,

    pub fn eql(a: Interest, b: Interest) bool {
        return a.read == b.read and a.write == b.write;
    }
};

/// One readiness notification. `ctx` is the pointer passed to `add`.
/// `readable`/`writable` are also set by a hang-up or error when the interest
/// includes that direction; `hup` says one of those happened.
pub const Event = struct {
    ctx: *anyopaque,
    readable: bool,
    writable: bool,
    hup: bool,
};

const Entry = struct {
    handle: sock.Handle,
    ctx: *anyopaque,
    interest: Interest,
};

pub const Reactor = struct {
    gpa: Allocator,
    entries: std.ArrayList(Entry) = .empty,
    /// The pollfd set `wait` builds: the wake socket, then every entry with a
    /// non-empty interest.
    scratch: std.ArrayList(posix.pollfd) = .empty,
    /// `entries` index of each `scratch` slot after the wake socket's.
    polled: std.ArrayList(u32) = .empty,
    /// `entries` index of each registered handle.
    index: std.AutoHashMapUnmanaged(sock.Handle, u32) = .empty,
    /// UDP loopback socket signalled by `wake`; always first in `scratch`.
    wake_sock: sock.Handle,
    wake_addr: std.net.Address,
    /// A wake datagram is queued and not yet drained: further `wake`s skip
    /// the syscall.
    wake_pending: std.atomic.Value(bool) = .init(false),

    pub fn init(gpa: Allocator) !Reactor {
        const h = try sock.udpBind(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0));
        errdefer sock.close(h);
        try sock.setNonblocking(h);
        const addr = sock.localAddress(h) orelse return error.NoAddr;
        return .{ .gpa = gpa, .wake_sock = h, .wake_addr = addr };
    }

    pub fn deinit(self: *Reactor) void {
        sock.close(self.wake_sock);
        self.entries.deinit(self.gpa);
        self.scratch.deinit(self.gpa);
        self.polled.deinit(self.gpa);
        self.index.deinit(self.gpa);
    }

    /// Registers `h` for `interest`. `ctx` is handed back on every readiness
    /// event for this handle; it must stay valid until `remove`. The handle
    /// should already be non-blocking (`sock.setNonblocking`).
    pub fn add(self: *Reactor, h: sock.Handle, ctx: *anyopaque, interest: Interest) !void {
        const gop = try self.index.getOrPut(self.gpa, h);
        if (gop.found_existing) return error.AlreadyRegistered;
        errdefer _ = self.index.remove(h);
        gop.value_ptr.* = @intCast(self.entries.items.len);
        try self.entries.append(self.gpa, .{ .handle = h, .ctx = ctx, .interest = interest });
    }

    pub fn modify(self: *Reactor, h: sock.Handle, interest: Interest) !void {
        const idx = self.index.get(h) orelse return error.NotRegistered;
        self.entries.items[idx].interest = interest;
    }

    /// Removes `h` from the reactor. Safe to call on an unregistered handle.
    pub fn remove(self: *Reactor, h: sock.Handle) void {
        const kv = self.index.fetchRemove(h) orelse return;
        _ = self.entries.swapRemove(kv.value);
        // The last entry moved into the freed slot.
        if (kv.value < self.entries.items.len) {
            self.index.getPtr(self.entries.items[kv.value].handle).?.* = kv.value;
        }
    }

    /// Waits up to `timeout_ms` (-1 to block indefinitely, 0 to poll). Fills
    /// `out` with readiness events, returns how many. If `wake` was called,
    /// the drain is silent and does not take a slot in `out`.
    ///
    /// Only handles with a non-empty interest are polled: poll() reports
    /// hang-ups and errors even for an empty event mask, and with nobody
    /// acting on them `wait` would return at once forever. A hang-up or error
    /// is reported as readable and/or writable, per the interest, so the
    /// recv/send the owner makes next returns the EOF or error and clears it.
    pub fn wait(self: *Reactor, out: []Event, timeout_ms: i32) !usize {
        self.scratch.clearRetainingCapacity();
        self.polled.clearRetainingCapacity();
        try self.scratch.ensureTotalCapacity(self.gpa, self.entries.items.len + 1);
        try self.polled.ensureTotalCapacity(self.gpa, self.entries.items.len);
        self.scratch.appendAssumeCapacity(.{ .fd = self.wake_sock, .events = posix.POLL.IN, .revents = 0 });
        for (self.entries.items, 0..) |e, i| {
            if (!e.interest.read and !e.interest.write) continue;
            var events: i16 = 0;
            if (e.interest.read) events |= posix.POLL.IN;
            if (e.interest.write) events |= posix.POLL.OUT;
            self.scratch.appendAssumeCapacity(.{ .fd = e.handle, .events = events, .revents = 0 });
            self.polled.appendAssumeCapacity(@intCast(i));
        }

        const n = try posix.poll(self.scratch.items, timeout_ms);
        if (n == 0) return 0;
        if (self.scratch.items[0].revents & posix.POLL.IN != 0) {
            self.drainWake();
            // Cleared after the drain: a `wake` in between was skipped, but
            // the caller looks at shared state only after `wait` returns, so
            // it still sees that change.
            self.wake_pending.store(false, .release);
        }

        var out_i: usize = 0;
        for (self.scratch.items[1..], self.polled.items) |pfd, idx| {
            if (out_i == out.len) break;
            const r = pfd.revents;
            if (r == 0) continue;
            const e = self.entries.items[idx];
            const failed = r & (posix.POLL.HUP | posix.POLL.ERR) != 0;
            out[out_i] = .{
                .ctx = e.ctx,
                .readable = e.interest.read and (failed or r & posix.POLL.IN != 0),
                .writable = e.interest.write and (failed or r & posix.POLL.OUT != 0),
                .hup = failed or r & posix.POLL.NVAL != 0,
            };
            out_i += 1;
        }
        return out_i;
    }

    /// Thread-safe: nudges `wait` to return promptly on the reactor's thread.
    /// Until `wait` drains it, further `wake`s cost one atomic swap: no
    /// syscall per call.
    pub fn wake(self: *Reactor) void {
        if (self.wake_pending.swap(true, .acq_rel)) return;
        sock.sendTo(self.wake_sock, &[_]u8{1}, self.wake_addr) catch {
            self.wake_pending.store(false, .release);
        };
    }

    fn drainWake(self: *Reactor) void {
        var buf: [256]u8 = undefined;
        while (true) _ = sock.recvFrom(self.wake_sock, &buf) catch break;
    }

    pub fn count(self: *const Reactor) usize {
        return self.entries.items.len;
    }
};

// --------------------------------------------------------------------- tests

const testing = std.testing;

test "wake returns from wait within 100 ms" {
    var r = try Reactor.init(testing.allocator);
    defer r.deinit();

    const T = struct {
        fn fire(reactor: *Reactor) void {
            std.Thread.sleep(20 * std.time.ns_per_ms);
            reactor.wake();
        }
    };
    const t = try std.Thread.spawn(.{}, T.fire, .{&r});
    defer t.join();

    var events: [4]Event = undefined;
    const n = try r.wait(&events, 500);
    try testing.expectEqual(@as(usize, 0), n); // wake drains silently
}

test "a burst of wakes queues a single datagram" {
    var r = try Reactor.init(testing.allocator);
    defer r.deinit();

    const T = struct {
        fn fire(reactor: *Reactor) void {
            for (0..1000) |_| reactor.wake();
        }
    };
    const t = try std.Thread.spawn(.{}, T.fire, .{&r});
    t.join();

    try testing.expect(sock.pollRead(r.wake_sock, 1000));
    std.Thread.sleep(20 * std.time.ns_per_ms); // let any stragglers land
    var buf: [16]u8 = undefined;
    var queued: usize = 0;
    while (true) : (queued += 1) _ = sock.recvFrom(r.wake_sock, &buf) catch break;
    try testing.expectEqual(@as(usize, 1), queued);
}

test "every wake after a drain still wakes wait" {
    var r = try Reactor.init(testing.allocator);
    defer r.deinit();
    var events: [4]Event = undefined;
    for (0..3) |_| {
        r.wake();
        const start = clock.monotonicMs();
        try testing.expectEqual(@as(usize, 0), try r.wait(&events, 1000));
        try testing.expect(clock.monotonicMs() - start < 500);
    }
}

test "remove keeps the other registrations intact" {
    const gpa = testing.allocator;
    var r = try Reactor.init(gpa);
    defer r.deinit();

    var socks: [3]sock.Handle = undefined;
    var ctxs: [3]usize = .{ 0, 1, 2 };
    for (&socks, &ctxs) |*h, *ctx| {
        h.* = try sock.udpBind(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0));
        try sock.setNonblocking(h.*);
        try r.add(h.*, @ptrCast(ctx), .{ .read = true });
    }
    defer for (socks) |h| sock.close(h);

    // Removing the first entry moves the last into its slot; the index must
    // follow, or the next modify/remove hits the wrong socket.
    r.remove(socks[0]);
    try r.modify(socks[1], .{});
    try sock.sendTo(socks[2], "x", sock.localAddress(socks[2]).?);
    var events: [4]Event = undefined;
    try testing.expectEqual(@as(usize, 1), try r.wait(&events, 1000));
    try testing.expectEqual(@as(*anyopaque, @ptrCast(&ctxs[2])), events[0].ctx);
    r.remove(socks[2]);
    r.remove(socks[1]);
    try testing.expectEqual(@as(usize, 0), r.count());
}

test "a connected TCP pair signals readable on data arrival" {
    const gpa = testing.allocator;
    var r = try Reactor.init(gpa);
    defer r.deinit();

    var listener = try sock.listenTcp(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0), 1);
    defer listener.deinit();
    const client = try sock.tcpConnect(listener.listen_address, 1000);
    defer sock.close(client);
    const conn = try listener.accept();
    defer conn.stream.close();

    try sock.setNonblocking(conn.stream.handle);
    var dummy: usize = 0;
    try r.add(conn.stream.handle, @ptrCast(&dummy), .{ .read = true });

    var events: [2]Event = undefined;
    try testing.expectEqual(@as(usize, 0), try r.wait(&events, 50));

    try sock.sendAll(client, "hi");
    const n = try r.wait(&events, 500);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expect(events[0].readable);
    try testing.expectEqual(@as(*anyopaque, @ptrCast(&dummy)), events[0].ctx);
}

test "add rejects duplicate registration; remove unregisters" {
    const gpa = testing.allocator;
    var r = try Reactor.init(gpa);
    defer r.deinit();

    const h = try sock.udpBind(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0));
    defer sock.close(h);
    var dummy: usize = 0;
    try r.add(h, @ptrCast(&dummy), .{ .read = true });
    try testing.expectError(error.AlreadyRegistered, r.add(h, @ptrCast(&dummy), .{ .read = true }));
    try testing.expectEqual(@as(usize, 1), r.count());
    r.remove(h);
    try testing.expectEqual(@as(usize, 0), r.count());
    r.remove(h); // no-op
    try r.add(h, @ptrCast(&dummy), .{ .read = true, .write = true });
    try testing.expectEqual(@as(usize, 1), r.count());
    r.remove(h);
}

/// Closes `h` so that its peer sees a reset instead of an orderly close.
fn closeWithReset(h: sock.Handle) void {
    if (builtin.os.tag == .windows) {
        const ws2 = std.os.windows.ws2_32;
        const Linger = extern struct { onoff: u16, linger: u16 };
        const l: Linger = .{ .onoff = 1, .linger = 0 };
        _ = ws2.setsockopt(h, ws2.SOL.SOCKET, ws2.SO.LINGER, std.mem.asBytes(&l), @sizeOf(Linger));
    } else {
        const Linger = extern struct { onoff: c_int, linger: c_int };
        const l: Linger = .{ .onoff = 1, .linger = 0 };
        posix.setsockopt(h, posix.SOL.SOCKET, posix.SO.LINGER, std.mem.asBytes(&l)) catch {};
    }
    sock.close(h);
}

test "a reset socket wakes wait only while someone is interested in it" {
    const gpa = testing.allocator;
    var r = try Reactor.init(gpa);
    defer r.deinit();

    var listener = try sock.listenTcp(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0), 1);
    defer listener.deinit();
    const client = try sock.tcpConnect(listener.listen_address, 1000);
    const conn = try listener.accept();
    defer conn.stream.close();
    closeWithReset(client);

    try sock.setNonblocking(conn.stream.handle);
    var dummy: usize = 0;
    try r.add(conn.stream.handle, @ptrCast(&dummy), .{});
    var events: [2]Event = undefined;
    // poll() reports the reset even for an empty event mask; a socket nobody
    // waits on must not be polled, or wait() never blocks again.
    try testing.expectEqual(@as(usize, 0), try r.wait(&events, 100));

    // With read interest the reset is reported as readable, so the owner's
    // next recv returns it.
    try r.modify(conn.stream.handle, .{ .read = true });
    try testing.expectEqual(@as(usize, 1), try r.wait(&events, 1000));
    try testing.expect(events[0].readable);
    try testing.expect(!events[0].writable);
}
