//! Minimal blocking socket helpers that behave the same on POSIX and Windows.
//! (std.net.Stream.read uses ReadFile on Windows, which is unreliable for sockets.)
const std = @import("std");
const builtin = @import("builtin");
const clock = @import("clock.zig");
const posix = std.posix;
const ws2 = std.os.windows.ws2_32;

const is_windows = builtin.os.tag == .windows;

pub const Handle = std.net.Stream.Handle;

/// `Timeout`: nothing to read yet -- the receive timeout expired, or a
/// non-blocking socket would block (POSIX reports both as EAGAIN).
pub const RecvError = error{ Timeout, ConnectionReset, RecvFailed };
pub const SendError = error{ ConnectionReset, SendFailed };

/// Returns 0 on orderly shutdown by the peer.
pub fn recv(h: Handle, buf: []u8) RecvError!usize {
    if (is_windows) {
        const len: i32 = @intCast(@min(buf.len, std.math.maxInt(i32)));
        const n = ws2.recv(h, buf.ptr, len, 0);
        if (n == ws2.SOCKET_ERROR) return switch (ws2.WSAGetLastError()) {
            .WSAETIMEDOUT, .WSAEWOULDBLOCK => error.Timeout,
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

/// Returns the first byte that is already in the OS receive buffer, without
/// consuming it (MSG_PEEK). Waits up to `timeout_ms` for a byte to arrive,
/// null on timeout, error.EndOfStream on orderly close.
pub fn peekByte(h: Handle, timeout_ms: i32) (RecvError || error{EndOfStream})!?u8 {
    if (!pollRead(h, timeout_ms)) return null;
    var b: [1]u8 = undefined;
    if (is_windows) {
        const n = ws2.recv(h, &b, 1, 0x2); // MSG_PEEK = 2
        if (n == ws2.SOCKET_ERROR) return switch (ws2.WSAGetLastError()) {
            .WSAETIMEDOUT => error.Timeout,
            .WSAECONNRESET, .WSAECONNABORTED, .WSAESHUTDOWN => error.ConnectionReset,
            else => error.RecvFailed,
        };
        if (n == 0) return error.EndOfStream;
        return b[0];
    }
    const n = posix.recv(h, &b, posix.MSG.PEEK) catch |err| return switch (err) {
        error.WouldBlock => null,
        error.ConnectionResetByPeer, error.ConnectionRefused, error.SocketNotConnected => error.ConnectionReset,
        else => error.RecvFailed,
    };
    if (n == 0) return error.EndOfStream;
    return b[0];
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
    setTimeout(h, if (is_windows) ws2.SO.RCVTIMEO else posix.SO.RCVTIMEO, ms);
}

/// 0 disables the timeout. A send that cannot make progress for `ms` fails.
pub fn setSendTimeout(h: Handle, ms: u32) void {
    setTimeout(h, if (is_windows) ws2.SO.SNDTIMEO else posix.SO.SNDTIMEO, ms);
}

fn setTimeout(h: Handle, opt: anytype, ms: u32) void {
    if (is_windows) {
        const v: u32 = ms;
        _ = ws2.setsockopt(h, ws2.SOL.SOCKET, opt, std.mem.asBytes(&v), @sizeOf(u32));
    } else {
        const tv: posix.timeval = .{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
        posix.setsockopt(h, posix.SOL.SOCKET, opt, std.mem.asBytes(&tv)) catch {};
    }
}

pub const ConnectError = error{
    ConnectionRefused,
    ConnectionTimedOut,
    NetworkUnreachable,
    HostUnreachable,
    AccessDenied,
    ConnectFailed,
};

/// Connects a TCP socket to `addr`, giving up after `timeout_ms`. The returned
/// socket is in blocking mode.
pub fn tcpConnect(addr: std.net.Address, timeout_ms: u32) ConnectError!Handle {
    return if (is_windows) tcpConnectWindows(addr, timeout_ms) else tcpConnectPosix(addr, timeout_ms);
}

fn tcpConnectPosix(addr: std.net.Address, timeout_ms: u32) ConnectError!Handle {
    const h = posix.socket(addr.any.family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP) catch
        return error.ConnectFailed;
    errdefer close(h);
    posix.connect(h, &addr.any, addr.getOsSockLen()) catch |err| switch (err) {
        error.WouldBlock => {
            var fds = [_]posix.pollfd{.{ .fd = h, .events = posix.POLL.OUT, .revents = 0 }};
            const n = posix.poll(&fds, @intCast(@min(timeout_ms, std.math.maxInt(i32)))) catch return error.ConnectFailed;
            if (n == 0) return error.ConnectionTimedOut;
            var code: i32 = 0;
            posix.getsockopt(h, posix.SOL.SOCKET, posix.SO.ERROR, std.mem.asBytes(&code)) catch return error.ConnectFailed;
            if (code != 0) return switch (@as(posix.E, @enumFromInt(code))) {
                .CONNREFUSED => error.ConnectionRefused,
                .TIMEDOUT => error.ConnectionTimedOut,
                .NETUNREACH => error.NetworkUnreachable,
                .HOSTUNREACH => error.HostUnreachable,
                .ACCES, .PERM => error.AccessDenied,
                else => error.ConnectFailed,
            };
        },
        error.ConnectionRefused => return error.ConnectionRefused,
        error.NetworkUnreachable => return error.NetworkUnreachable,
        error.AccessDenied, error.PermissionDenied => return error.AccessDenied,
        error.ConnectionTimedOut => return error.ConnectionTimedOut,
        else => return error.ConnectFailed,
    };
    // Back to blocking mode for the relay threads.
    const flags = posix.fcntl(h, posix.F.GETFL, 0) catch return error.ConnectFailed;
    var o: posix.O = @bitCast(@as(std.meta.Int(.unsigned, @bitSizeOf(posix.O)), @truncate(flags)));
    o.NONBLOCK = false;
    _ = posix.fcntl(h, posix.F.SETFL, @as(std.meta.Int(.unsigned, @bitSizeOf(posix.O)), @bitCast(o))) catch return error.ConnectFailed;
    return h;
}

fn tcpConnectWindows(addr: std.net.Address, timeout_ms: u32) ConnectError!Handle {
    const h = posix.socket(addr.any.family, posix.SOCK.STREAM, posix.IPPROTO.TCP) catch return error.ConnectFailed;
    errdefer close(h);
    var nonblocking: u32 = 1;
    if (ws2.ioctlsocket(h, ws2.FIONBIO, &nonblocking) == ws2.SOCKET_ERROR) return error.ConnectFailed;
    // Windows answers a RST to its SYN by retrying the SYN twice, so a closed
    // port takes ~2 s to report "refused". Allowing one retransmission cuts that
    // to ~0.5 s and still tolerates a single lost SYN. Best effort: older
    // Windows versions lack SIO_TCP_INITIAL_RTO.
    const SIO_TCP_INITIAL_RTO: u32 = 0x98000011;
    const InitialRto = extern struct { rtt: u16, max_syn_retransmissions: u8 };
    var rto: InitialRto = .{ .rtt = 0xffff, .max_syn_retransmissions = 1 };
    var returned: u32 = 0;
    _ = ws2.WSAIoctl(h, SIO_TCP_INITIAL_RTO, &rto, @sizeOf(InitialRto), null, 0, &returned, null, null);

    if (ws2.connect(h, &addr.any, @intCast(addr.getOsSockLen())) == ws2.SOCKET_ERROR) {
        switch (ws2.WSAGetLastError()) {
            .WSAEWOULDBLOCK => {},
            else => |e| return mapWsaConnectError(@intFromEnum(e)),
        }
        // select() reports a finished connect as writable and a failed one in
        // the except set (more reliable than WSAPoll for failed connects).
        var wfds: ws2.fd_set = .{ .fd_count = 1, .fd_array = undefined };
        var efds: ws2.fd_set = .{ .fd_count = 1, .fd_array = undefined };
        wfds.fd_array[0] = h;
        efds.fd_array[0] = h;
        const tv: ws2.timeval = .{ .sec = @intCast(timeout_ms / 1000), .usec = @intCast((timeout_ms % 1000) * 1000) };
        const n = ws2.select(0, null, &wfds, &efds, &tv);
        if (n == ws2.SOCKET_ERROR) return error.ConnectFailed;
        if (n == 0) return error.ConnectionTimedOut;
        var code: i32 = 0;
        var len: i32 = @sizeOf(i32);
        if (ws2.getsockopt(h, ws2.SOL.SOCKET, ws2.SO.ERROR, std.mem.asBytes(&code), &len) == ws2.SOCKET_ERROR)
            return error.ConnectFailed;
        if (code != 0) return mapWsaConnectError(@intCast(code));
    }
    var blocking: u32 = 0;
    if (ws2.ioctlsocket(h, ws2.FIONBIO, &blocking) == ws2.SOCKET_ERROR) return error.ConnectFailed;
    return h;
}

/// Raw Winsock error codes (SO_ERROR may hold values outside std's enum).
fn mapWsaConnectError(code: u32) ConnectError {
    return switch (code) {
        10061 => error.ConnectionRefused, // WSAECONNREFUSED
        10060 => error.ConnectionTimedOut, // WSAETIMEDOUT
        10051 => error.NetworkUnreachable, // WSAENETUNREACH
        10065 => error.HostUnreachable, // WSAEHOSTUNREACH
        10013 => error.AccessDenied, // WSAEACCES
        else => error.ConnectFailed,
    };
}

test "tcpConnect: refused fast, unroutable times out" {
    // Nothing listens on port 1 of loopback.
    try std.testing.expectError(error.ConnectionRefused, tcpConnect(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 1), 5000));
    // A blackholed address must give up close to the timeout, not after the OS default.
    const start = clock.monotonicMs();
    if (tcpConnect(std.net.Address.initIp4(.{ 10, 255, 255, 1 }, 9), 300)) |h| {
        close(h);
    } else |_| {}
    try std.testing.expect(clock.monotonicMs() - start < 2000);
}

/// Puts a socket in non-blocking mode. Reads and writes that would block
/// return `error.WouldBlock` instead of waiting.
pub fn setNonblocking(h: Handle) !void {
    if (is_windows) {
        var mode: u32 = 1;
        if (ws2.ioctlsocket(h, ws2.FIONBIO, &mode) == ws2.SOCKET_ERROR) return error.SetNonblockingFailed;
        return;
    }
    const flags = posix.fcntl(h, posix.F.GETFL, 0) catch return error.SetNonblockingFailed;
    var o: posix.O = @bitCast(@as(std.meta.Int(.unsigned, @bitSizeOf(posix.O)), @truncate(flags)));
    o.NONBLOCK = true;
    _ = posix.fcntl(h, posix.F.SETFL, @as(std.meta.Int(.unsigned, @bitSizeOf(posix.O)), @bitCast(o))) catch return error.SetNonblockingFailed;
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

/// Opens a listening TCP socket. On Windows it uses SO_EXCLUSIVEADDRUSE: with
/// the default (or SO_REUSEADDR) another local process could bind a more
/// specific address on the same port and silently take over our connections.
/// Elsewhere SO_REUSEADDR only allows quick restarts over TIME_WAIT.
pub fn listenTcp(addr: std.net.Address, backlog: u31) !std.net.Server {
    const h = try posix.socket(addr.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP);
    errdefer close(h);
    const one: i32 = 1;
    if (is_windows) {
        const SO_EXCLUSIVEADDRUSE: i32 = ~@as(i32, ws2.SO.REUSEADDR);
        _ = ws2.setsockopt(h, ws2.SOL.SOCKET, SO_EXCLUSIVEADDRUSE, std.mem.asBytes(&one), @sizeOf(i32));
    } else {
        try posix.setsockopt(h, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));
    }
    try posix.bind(h, &addr.any, addr.getOsSockLen());
    try posix.listen(h, backlog);
    return .{ .listen_address = localAddress(h) orelse addr, .stream = .{ .handle = h } };
}

/// True if `ip` is assigned to an interface on this machine.
pub fn isLocalAddress(ip: [4]u8) bool {
    const h = udpBind(std.net.Address.initIp4(ip, 0)) catch return false;
    close(h);
    return true;
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
            .WSAETIMEDOUT, .WSAEWOULDBLOCK => error.Timeout,
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
