//! Unprivileged ICMP echo ("is this host up?") for the agent.
//!   Windows: IcmpSendEcho (iphlpapi), no admin rights needed.
//!   Linux/macOS: SOCK_DGRAM ICMP socket; falls back to the system `ping`
//!   binary when unprivileged ICMP sockets are not permitted.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub const Result = struct { ok: bool, rtt_ms: u16 = 0 };

pub fn echo(gpa: std.mem.Allocator, addr: [4]u8, timeout_ms: u32) Result {
    if (builtin.os.tag == .windows) return windowsEcho(addr, timeout_ms);
    return socketEcho(addr, timeout_ms) catch pingCommand(gpa, addr, timeout_ms);
}

// ------------------------------------------------------------------ Windows

const win = struct {
    const HANDLE = std.os.windows.HANDLE;
    extern "iphlpapi" fn IcmpCreateFile() callconv(.winapi) HANDLE;
    extern "iphlpapi" fn IcmpCloseHandle(h: HANDLE) callconv(.winapi) std.os.windows.BOOL;
    extern "iphlpapi" fn IcmpSendEcho(
        h: HANDLE,
        dest: u32,
        request: ?*const anyopaque,
        request_size: u16,
        options: ?*anyopaque,
        reply: *anyopaque,
        reply_size: u32,
        timeout: u32,
    ) callconv(.winapi) u32;
};

fn windowsEcho(addr: [4]u8, timeout_ms: u32) Result {
    const h = win.IcmpCreateFile();
    if (h == std.os.windows.INVALID_HANDLE_VALUE) return .{ .ok = false };
    defer _ = win.IcmpCloseHandle(h);
    const payload = "zunnel-ping-0123";
    // ICMP_ECHO_REPLY (+ payload + 8 bytes for an ICMP error), generously sized.
    var reply: [256]u8 align(8) = undefined;
    const n = win.IcmpSendEcho(h, @bitCast(addr), payload, payload.len, null, &reply, reply.len, timeout_ms);
    if (n == 0) return .{ .ok = false };
    // struct ICMP_ECHO_REPLY { IPAddr Address; ULONG Status; ULONG RoundTripTime; ... }
    const status = std.mem.readInt(u32, reply[4..8], .little);
    const rtt = std.mem.readInt(u32, reply[8..12], .little);
    return .{ .ok = status == 0, .rtt_ms = @intCast(@min(rtt, std.math.maxInt(u16))) };
}

// -------------------------------------------------------------------- POSIX

fn checksum(data: []const u8) u16 {
    var s: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) s += std.mem.readInt(u16, data[i..][0..2], .big);
    if (data.len & 1 == 1) s += @as(u32, data[data.len - 1]) << 8;
    while (s >> 16 != 0) s = (s & 0xffff) + (s >> 16);
    return ~@as(u16, @truncate(s));
}

fn socketEcho(addr: [4]u8, timeout_ms: u32) !Result {
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, posix.IPPROTO.ICMP);
    defer posix.close(fd);

    var req = [_]u8{ 8, 0, 0, 0, 0, 0, 0, 1 } ++ "zunnel-ping-0123".*;
    std.mem.writeInt(u16, req[2..4], checksum(&req), .big);
    const dest = std.net.Address.initIp4(addr, 0);
    const start = std.time.milliTimestamp();
    _ = try posix.sendto(fd, &req, 0, &dest.any, dest.getOsSockLen());

    var buf: [1500]u8 = undefined;
    while (true) {
        const elapsed = std.time.milliTimestamp() - start;
        if (elapsed >= timeout_ms) return .{ .ok = false };
        var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
        if (try posix.poll(&fds, @intCast(@as(i64, timeout_ms) - elapsed)) == 0) return .{ .ok = false };
        const n = try posix.recv(fd, &buf, 0);
        // Linux delivers the bare ICMP message, BSD/macOS include the IP header.
        var msg = buf[0..n];
        if (msg.len >= 20 and msg[0] >> 4 == 4) msg = msg[@as(usize, msg[0] & 0x0f) * 4 ..];
        if (msg.len >= 8 and msg[0] == 0) {
            const rtt = std.time.milliTimestamp() - start;
            return .{ .ok = true, .rtt_ms = @intCast(@min(rtt, std.math.maxInt(u16))) };
        }
    }
}

fn pingCommand(gpa: std.mem.Allocator, addr: [4]u8, timeout_ms: u32) Result {
    var ip_buf: [16]u8 = undefined;
    const ip = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] }) catch return .{ .ok = false };
    var secs_buf: [8]u8 = undefined;
    const secs = std.fmt.bufPrint(&secs_buf, "{d}", .{@max(1, (timeout_ms + 999) / 1000)}) catch return .{ .ok = false };
    const wait_flag = if (builtin.os.tag.isDarwin()) "-t" else "-W";
    const start = std.time.milliTimestamp();
    const res = std.process.Child.run(.{ .allocator = gpa, .argv = &.{ "ping", "-c", "1", wait_flag, secs, ip } }) catch
        return .{ .ok = false };
    gpa.free(res.stdout);
    gpa.free(res.stderr);
    const ok = switch (res.term) {
        .Exited => |code| code == 0,
        else => false,
    };
    const rtt = std.time.milliTimestamp() - start;
    return .{ .ok = ok, .rtt_ms = @intCast(@min(rtt, std.math.maxInt(u16))) };
}
