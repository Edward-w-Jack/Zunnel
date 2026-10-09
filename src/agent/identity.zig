//! Stable agent identity, derived from the host so nothing is written to the
//! target: hash(OS machine ID, user). The same agent on the same host and
//! account always gets the same id, across reboots and reconnects.
const std = @import("std");
const builtin = @import("builtin");

pub const len = 16;

/// The identity for a given machine ID and user (hex, 16 chars).
pub fn derive(machine_id: []const u8, user: []const u8) [len]u8 {
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    h.update("zunnel-agent-id\x00");
    h.update(std.mem.trim(u8, machine_id, " \t\r\n"));
    h.update("\x00");
    h.update(user);
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return std.fmt.bytesToHex(digest[0 .. len / 2], .lower);
}

/// Reads the OS machine ID without privileges. Falls back to the hostname.
pub fn machineId(buf: []u8) []const u8 {
    return switch (builtin.os.tag) {
        .windows => windowsMachineGuid(buf),
        .linux => readFirst(buf, &.{ "/etc/machine-id", "/var/lib/dbus/machine-id" }),
        .macos => darwinUuid(buf),
        else => null,
    } orelse hostname(buf);
}

fn readFirst(buf: []u8, paths: []const []const u8) ?[]const u8 {
    for (paths) |p| {
        const data = std.fs.cwd().readFile(p, buf) catch continue;
        const t = std.mem.trim(u8, data, " \t\r\n");
        if (t.len > 0) return t;
    }
    return null;
}

fn hostname(buf: []u8) []const u8 {
    if (builtin.os.tag == .windows) return "unknown-host";
    var hb: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const name = std.posix.gethostname(&hb) catch return "unknown-host";
    const n = @min(name.len, buf.len);
    @memcpy(buf[0..n], name[0..n]);
    return buf[0..n];
}

const win = struct {
    const HKEY_LOCAL_MACHINE: std.os.windows.HKEY = @ptrFromInt(0x80000002);
    const RRF_RT_REG_SZ = 0x00000002;
    /// Read the 64-bit registry view even from a 32-bit agent.
    const RRF_SUBKEY_WOW6464KEY = 0x00010000;
    extern "advapi32" fn RegGetValueW(
        hkey: std.os.windows.HKEY,
        sub_key: [*:0]const u16,
        value: [*:0]const u16,
        flags: u32,
        type_out: ?*u32,
        data: ?*anyopaque,
        data_len: *u32,
    ) callconv(.winapi) i32;
};

fn windowsMachineGuid(buf: []u8) ?[]const u8 {
    var wide: [64]u16 = undefined;
    var size: u32 = @sizeOf(@TypeOf(wide));
    const rc = win.RegGetValueW(
        win.HKEY_LOCAL_MACHINE,
        std.unicode.utf8ToUtf16LeStringLiteral("SOFTWARE\\Microsoft\\Cryptography"),
        std.unicode.utf8ToUtf16LeStringLiteral("MachineGuid"),
        win.RRF_RT_REG_SZ | win.RRF_SUBKEY_WOW6464KEY,
        null,
        &wide,
        &size,
    );
    if (rc != 0 or size < 2) return null;
    const chars = std.mem.sliceTo(wide[0 .. size / 2], 0);
    const n = std.unicode.utf16LeToUtf8(buf, chars) catch return null;
    return buf[0..n];
}

fn darwinUuid(buf: []u8) ?[]const u8 {
    var len_out: usize = buf.len;
    std.posix.sysctlbynameZ("kern.uuid", buf.ptr, &len_out, null, 0) catch return null;
    return std.mem.sliceTo(buf[0..len_out], 0);
}

test derive {
    const a = derive("0123456789abcdef0123456789abcdef", "alice");
    try std.testing.expectEqualStrings(&a, &derive("0123456789abcdef0123456789abcdef\n", "alice"));
    try std.testing.expect(!std.mem.eql(u8, &a, &derive("0123456789abcdef0123456789abcdef", "bob")));
    try std.testing.expectEqual(@as(usize, 16), a.len);
}

test machineId {
    var buf: [128]u8 = undefined;
    const id = machineId(&buf);
    try std.testing.expect(id.len > 0);
    // Stable across calls.
    var buf2: [128]u8 = undefined;
    try std.testing.expectEqualStrings(id, machineId(&buf2));
}
