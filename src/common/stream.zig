//! A byte stream that the link runs over: either raw TCP (the current ZNL5
//! wire) or TLS on top of TCP (ZNL6, added in P2). `Stream` is a tiny vtable
//! so `link.zig` doesn't care which it is.
//!
//! Error sets are shared across backends; a TLS backend maps its own errors to
//! the same set (TlsFailure for anything that is not an obvious socket error).
const std = @import("std");
const sock = @import("sock.zig");

pub const RecvError = sock.RecvError || error{TlsFailure};
pub const SendError = sock.SendError || error{TlsFailure};

pub const Stream = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Returns 0 on orderly shutdown by the peer.
        recv: *const fn (ctx: *anyopaque, buf: []u8) RecvError!usize,
        sendAll: *const fn (ctx: *anyopaque, data: []const u8) SendError!void,
        shutdown: *const fn (ctx: *anyopaque, how: sock.How) void,
        /// Tears the stream down and frees the backing object.
        close: *const fn (ctx: *anyopaque) void,
        setRecvTimeout: *const fn (ctx: *anyopaque, ms: u32) void,
        setSendTimeout: *const fn (ctx: *anyopaque, ms: u32) void,
    };

    pub fn recv(self: Stream, buf: []u8) RecvError!usize {
        return self.vtable.recv(self.ctx, buf);
    }

    pub fn sendAll(self: Stream, data: []const u8) SendError!void {
        return self.vtable.sendAll(self.ctx, data);
    }

    /// Fills `buf` completely or fails with error.EndOfStream.
    pub fn recvExact(self: Stream, buf: []u8) (RecvError || error{EndOfStream})!void {
        var off: usize = 0;
        while (off < buf.len) {
            const n = try self.recv(buf[off..]);
            if (n == 0) return error.EndOfStream;
            off += n;
        }
    }

    pub fn shutdown(self: Stream, how: sock.How) void {
        self.vtable.shutdown(self.ctx, how);
    }

    pub fn close(self: Stream) void {
        self.vtable.close(self.ctx);
    }

    pub fn setRecvTimeout(self: Stream, ms: u32) void {
        self.vtable.setRecvTimeout(self.ctx, ms);
    }

    pub fn setSendTimeout(self: Stream, ms: u32) void {
        self.vtable.setSendTimeout(self.ctx, ms);
    }
};

/// Raw TCP; the current ZNL5 transport. Allocated so `close` can free it.
pub const TcpStream = struct {
    gpa: std.mem.Allocator,
    handle: sock.Handle,

    /// Takes ownership of `handle`: the returned Stream closes it on `close`.
    pub fn wrap(gpa: std.mem.Allocator, handle: sock.Handle) std.mem.Allocator.Error!Stream {
        const s = try gpa.create(TcpStream);
        s.* = .{ .gpa = gpa, .handle = handle };
        return .{ .ctx = s, .vtable = &vtable };
    }

    const vtable: Stream.VTable = .{
        .recv = recvFn,
        .sendAll = sendAllFn,
        .shutdown = shutdownFn,
        .close = closeFn,
        .setRecvTimeout = setRecvTimeoutFn,
        .setSendTimeout = setSendTimeoutFn,
    };

    fn self(ctx: *anyopaque) *TcpStream {
        return @ptrCast(@alignCast(ctx));
    }

    fn recvFn(ctx: *anyopaque, buf: []u8) RecvError!usize {
        return sock.recv(self(ctx).handle, buf);
    }

    fn sendAllFn(ctx: *anyopaque, data: []const u8) SendError!void {
        return sock.sendAll(self(ctx).handle, data);
    }

    fn shutdownFn(ctx: *anyopaque, how: sock.How) void {
        sock.shutdown(self(ctx).handle, how);
    }

    fn closeFn(ctx: *anyopaque) void {
        const s = self(ctx);
        sock.close(s.handle);
        s.gpa.destroy(s);
    }

    fn setRecvTimeoutFn(ctx: *anyopaque, ms: u32) void {
        sock.setRecvTimeout(self(ctx).handle, ms);
    }

    fn setSendTimeoutFn(ctx: *anyopaque, ms: u32) void {
        sock.setSendTimeout(self(ctx).handle, ms);
    }
};

test "TcpStream round trip on loopback" {
    const gpa = std.testing.allocator;
    var server = try sock.listenTcp(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0), 1);
    defer server.deinit();

    const T = struct {
        fn accept(s: *std.net.Server, gpa_: std.mem.Allocator, err_out: *?anyerror) void {
            run(s, gpa_) catch |err| {
                err_out.* = err;
            };
        }
        fn run(s: *std.net.Server, gpa_: std.mem.Allocator) !void {
            const conn = try s.accept();
            const stream = try TcpStream.wrap(gpa_, conn.stream.handle);
            defer stream.close();
            var buf: [5]u8 = undefined;
            try stream.recvExact(&buf);
            try std.testing.expectEqualStrings("hello", &buf);
            try stream.sendAll("world");
        }
    };
    var srv_err: ?anyerror = null;
    const srv = try std.Thread.spawn(.{}, T.accept, .{ &server, gpa, &srv_err });

    const h = try sock.tcpConnect(server.listen_address, 2000);
    const client = try TcpStream.wrap(gpa, h);
    defer client.close();
    try client.sendAll("hello");
    var buf: [5]u8 = undefined;
    try client.recvExact(&buf);
    try std.testing.expectEqualStrings("world", &buf);
    srv.join();
    if (srv_err) |err| return err;
}
