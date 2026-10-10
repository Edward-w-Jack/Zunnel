//! Startup checks: the server always runs elevated with a TUN, so fail fast with
//! a clear message instead of at the first `start`.
const std = @import("std");
const builtin = @import("builtin");

/// Returns null when the server can create TUN interfaces, otherwise a message
/// explaining what is missing.
pub fn check(tun_name: []const u8) ?[]const u8 {
    return switch (builtin.os.tag) {
        .windows => checkWindows(),
        .linux => checkLinux(tun_name),
        else => null,
    };
}

const win = struct {
    const BOOL = std.os.windows.BOOL;
    extern "shell32" fn IsUserAnAdmin() callconv(.winapi) BOOL;
    extern "kernel32" fn LoadLibraryExW(name: [*:0]const u16, file: ?std.os.windows.HANDLE, flags: u32) callconv(.winapi) ?std.os.windows.HMODULE;
    extern "kernel32" fn FreeLibrary(module: std.os.windows.HMODULE) callconv(.winapi) BOOL;
};

fn checkWindows() ?[]const u8 {
    if (win.IsUserAnAdmin() == 0)
        return "zunnel-server must run as Administrator (it creates Wintun adapters and routes).\n" ++
            "Right-click your terminal and choose \"Run as administrator\".";
    // Same search flags as tun_windows: next to the exe, then System32.
    const flags = 0x00000200 | 0x00000800;
    const module = win.LoadLibraryExW(std.unicode.utf8ToUtf16LeStringLiteral("wintun.dll"), null, flags) orelse
        return "wintun.dll not found. Download it from https://www.wintun.net and place the amd64\n" ++
            "(or arm64) wintun.dll next to zunnel-server.exe.";
    _ = win.FreeLibrary(module);
    return null;
}

fn checkLinux(tun_name: []const u8) ?[]const u8 {
    if (std.os.linux.geteuid() == 0) return null;
    // A persistent TUN owned by this user works without root.
    var buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&buf, "/sys/class/net/{s}", .{tun_name}) catch return null;
    std.fs.accessAbsolute(path, .{}) catch return "zunnel-server needs root to create its TUN interface. Run it with sudo, or\n" ++
        "pre-create a persistent interface owned by your user:\n" ++
        "  sudo ip tuntap add user $USER mode tun <name>   (and pass -tun <name>)";
    return null;
}
