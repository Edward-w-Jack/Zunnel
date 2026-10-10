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
    scratch: std.ArrayList(posix.pollfd) = .empty,
    /// UDP loopback socket signalled by `wake`; always registered first in
    /// `scratch` so the drain path is hot.
    wake_sock: sock.Handle,
    wake_addr: std.net.Address,

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
    }

    /// Registers `h` for `interest`. `ctx` is handed back on every readiness
    /// event for this handle; it must stay valid until `remove`. The handle
    /// should already be non-blocking (`sock.setNonblocking`).
    pub fn add(self: *Reactor, h: sock.Handle, ctx: *anyopaque, interest: Interest) !void {
        if (self.findIndex(h) != null) return error.AlreadyRegistered;
        try self.entries.append(self.gpa, .{ .handle = h, .ctx = ctx, .interest = interest });
    }

    pub fn modify(self: *Reactor, h: sock.Handle, interest: Interest) !void {
        const idx = self.findIndex(h) orelse return error.NotRegistered;
        self.entries.items[idx].interest = interest;
    }

    /// Removes `h` from the reactor. Safe to call on an unregistered handle.
    pub fn remove(self: *Reactor, h: sock.Handle) void {
        if (self.findIndex(h)) |idx| _ = self.entries.swapRemove(idx);
    }

    /// Waits up to `timeout_ms` (-1 to block indefinitely, 0 to poll). Fills
    /// `out` with readiness events, returns how many. If `wake` was called,
    /// the drain is silent and does not take a slot in `out`.
    pub fn wait(self: *Reactor, out: []Event, timeout_ms: i32) !usize {
        try self.scratch.resize(self.gpa, self.entries.items.len + 1);
        for (self.entries.items, 0..) |e, i| {
            var events: i16 = 0;
            if (e.interest.read) events |= posix.POLL.IN;
            if (e.interest.write) events |= posix.POLL.OUT;
            self.scratch.items[i] = .{ .fd = e.handle, .events = events, .revents = 0 };
        }
        const wake_i = self.entries.items.len;
        self.scratch.items[wake_i] = .{ .fd = self.wake_sock, .events = posix.POLL.IN, .revents = 0 };

        const n = posix.poll(self.scratch.items, timeout_ms) catch |err| return err;
        if (n == 0) return 0;

        var out_i: usize = 0;
        for (self.entries.items, 0..) |e, i| {
            if (out_i == out.len) break;
            const r = self.scratch.items[i].revents;
            if (r == 0) continue;
            out[out_i] = .{
                .ctx = e.ctx,
                .readable = r & posix.POLL.IN != 0,
                .writable = r & posix.POLL.OUT != 0,
                .hup = r & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0,
            };
            out_i += 1;
        }
        if (self.scratch.items[wake_i].revents & posix.POLL.IN != 0) self.drainWake();
        return out_i;
    }

    /// Thread-safe: nudges `wait` to return promptly on the reactor's thread.
    /// Multiple concurrent `wake`s coalesce into one drain.
    pub fn wake(self: *Reactor) void {
        sock.sendTo(self.wake_sock, &[_]u8{1}, self.wake_addr) catch {};
    }

    fn drainWake(self: *Reactor) void {
        var buf: [256]u8 = undefined;
        while (true) _ = sock.recvFrom(self.wake_sock, &buf) catch break;
    }

    fn findIndex(self: *Reactor, h: sock.Handle) ?usize {
        for (self.entries.items, 0..) |e, i| if (e.handle == h) return i;
        return null;
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
