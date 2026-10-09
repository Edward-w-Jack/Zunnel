//! Minimal blocking socket helpers that behave the same on POSIX and Windows.
//! (std.net.Stream.read uses ReadFile on Windows, which is unreliable for sockets.)
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const ws2 = std.os.windows.ws2_32;

const is_windows = builtin.os.tag == .windows;

pub const Handle = std.net.Stream.Handle;

pub const RecvError = error{ Timeout, ConnectionReset, RecvFailed };
pub const SendError = error{ ConnectionReset, SendFailed };

/// Returns 0 on orderly shutdown by the peer.
pub fn recv(h: Handle, buf: []u8) RecvError!usize {
    if (is_windows) {
        const len: i32 = @intCast(@min(buf.len, std.math.maxInt(i32)));
        const n = ws2.recv(h, buf.ptr, len, 0);
        if (n == ws2.SOCKET_ERROR) return switch (ws2.WSAGetLastError()) {
            .WSAETIMEDOUT => error.Timeout,
            .WSAECONNRESET, .WSAECONNABORTED, .WSAESHUTDOWN => error.ConnectionReset,
            else => error.RecvFailed,
        };
        return @intCast(n);
    }
    return posix.recv(h, buf, 0) catch |err| switch (err) {
        error.WouldBlock => error.Timeout,
        error.ConnectionResetByPeer, error.ConnectionRefused, error.SocketNotConnected => error.ConnectionReset,
        else => error.RecvFailed,
    };
}

/// Fills `buf` completely or fails with error.EndOfStream.
pub fn recvExact(h: Handle, buf: []u8) (RecvError || error{EndOfStream})!void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = try recv(h, buf[off..]);
        if (n == 0) return error.EndOfStream;
        off += n;
    }
}

pub fn send(h: Handle, data: []const u8) SendError!usize {
    if (is_windows) {
        const len: i32 = @intCast(@min(data.len, std.math.maxInt(i32)));
        const n = ws2.send(h, data.ptr, len, 0);
        if (n == ws2.SOCKET_ERROR) return switch (ws2.WSAGetLastError()) {
            .WSAECONNRESET, .WSAECONNABORTED, .WSAESHUTDOWN => error.ConnectionReset,
            else => error.SendFailed,
        };
        return @intCast(n);
    }
    const flags: u32 = if (@hasDecl(posix.MSG, "NOSIGNAL")) posix.MSG.NOSIGNAL else 0;
    return posix.send(h, data, flags) catch |err| switch (err) {
        error.ConnectionResetByPeer, error.BrokenPipe => error.ConnectionReset,
        else => error.SendFailed,
    };
}

pub fn sendAll(h: Handle, data: []const u8) SendError!void {
    var off: usize = 0;
    while (off < data.len) off += try send(h, data[off..]);
}

pub const How = enum { recv, send, both };

pub fn shutdown(h: Handle, how: How) void {
    posix.shutdown(h, switch (how) {
        .recv => .recv,
        .send => .send,
        .both => .both,
    }) catch {};
}

pub fn close(h: Handle) void {
    (std.net.Stream{ .handle = h }).close();
}

/// 0 disables the timeout.
pub fn setRecvTimeout(h: Handle, ms: u32) void {
    if (is_windows) {
        const v: u32 = ms;
        _ = ws2.setsockopt(h, ws2.SOL.SOCKET, ws2.SO.RCVTIMEO, std.mem.asBytes(&v), @sizeOf(u32));
    } else {
        const tv: posix.timeval = .{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
        posix.setsockopt(h, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    }
}

pub fn setKeepAlive(h: Handle) void {
    const one: i32 = 1;
    if (is_windows) {
        _ = ws2.setsockopt(h, ws2.SOL.SOCKET, ws2.SO.KEEPALIVE, std.mem.asBytes(&one), @sizeOf(i32));
    } else {
        posix.setsockopt(h, posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&one)) catch {};
    }
}

pub fn setNoDelay(h: Handle) void {
    const one: i32 = 1;
    if (is_windows) {
        _ = ws2.setsockopt(h, ws2.IPPROTO.TCP, ws2.TCP.NODELAY, std.mem.asBytes(&one), @sizeOf(i32));
    } else {
        posix.setsockopt(h, posix.IPPROTO.TCP, posix.TCP.NODELAY, std.mem.asBytes(&one)) catch {};
    }
}

/// Waits up to `timeout_ms` for `h` to become readable (or to have a pending accept).
pub fn pollRead(h: Handle, timeout_ms: i32) bool {
    var fds = [_]posix.pollfd{.{ .fd = h, .events = posix.POLL.IN, .revents = 0 }};
    const n = posix.poll(&fds, timeout_ms) catch return false;
    return n > 0;
}

/// Opens a UDP socket bound to `addr`.
pub fn udpBind(addr: std.net.Address) !Handle {
    const h = try posix.socket(addr.any.family, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, posix.IPPROTO.UDP);
    errdefer close(h);
    try posix.bind(h, &addr.any, addr.getOsSockLen());
    return h;
}

pub fn recvFrom(h: Handle, buf: []u8) RecvError!struct { usize, std.net.Address } {
    var addr: std.net.Address = undefined;
    if (is_windows) {
        var wlen: i32 = @sizeOf(std.net.Address);
        const len: i32 = @intCast(@min(buf.len, std.math.maxInt(i32)));
        const n = ws2.recvfrom(h, buf.ptr, len, 0, &addr.any, &wlen);
        if (n == ws2.SOCKET_ERROR) return switch (ws2.WSAGetLastError()) {
            .WSAETIMEDOUT => error.Timeout,
            .WSAECONNRESET, .WSAEMSGSIZE => error.ConnectionReset,
            else => error.RecvFailed,
        };
        return .{ @intCast(n), addr };
    }
    var len: posix.socklen_t = @sizeOf(std.net.Address);
    const n = posix.recvfrom(h, buf, 0, &addr.any, &len) catch |err| return switch (err) {
        error.WouldBlock => error.Timeout,
        error.ConnectionResetByPeer, error.ConnectionRefused => error.ConnectionReset,
        else => error.RecvFailed,
    };
    return .{ n, addr };
}

pub fn sendTo(h: Handle, data: []const u8, addr: std.net.Address) SendError!void {
    if (is_windows) {
        const n = ws2.sendto(h, data.ptr, @intCast(data.len), 0, &addr.any, @intCast(addr.getOsSockLen()));
        if (n == ws2.SOCKET_ERROR) return error.SendFailed;
        return;
    }
    _ = posix.sendto(h, data, 0, &addr.any, addr.getOsSockLen()) catch return error.SendFailed;
}

/// The local address a socket is bound to.
pub fn localAddress(h: Handle) ?std.net.Address {
    var addr: std.net.Address = undefined;
    var len: posix.socklen_t = @sizeOf(std.net.Address);
    posix.getsockname(h, &addr.any, &len) catch return null;
    return addr;
}

/// Opens a UDP socket connected to `addr`.
pub fn udpConnect(addr: std.net.Address) !Handle {
    const h = try posix.socket(addr.any.family, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, posix.IPPROTO.UDP);
    errdefer close(h);
    try posix.connect(h, &addr.any, addr.getOsSockLen());
    return h;
}
