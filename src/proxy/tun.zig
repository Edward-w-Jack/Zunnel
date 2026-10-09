//! Platform TUN device. Every backend exposes:
//!   open(gpa, name, index) !Tun
//!   read(*Tun, buf) !usize      -- blocks for at most ~500ms, 0 on timeout
//!   write(*Tun, pkt) void       -- thread safe, drops on failure
//!   addRoute(*Tun, cidr) !void / delRoute(*Tun, cidr) !void
//!   close(*Tun) void
const std = @import("std");
const builtin = @import("builtin");

pub const mtu = 1500;

/// Address of tunnel `index` (benchmark range 198.18.0.0/15, never used on real
/// networks). Windows needs one on the adapter; lwIP needs one on the netif.
pub fn localAddress(index: u8) [4]u8 {
    return .{ 198, 18, 0, index +| 1 };
}

pub const Tun = switch (builtin.os.tag) {
    .linux => @import("tun_linux.zig").Tun,
    .windows => @import("tun_windows.zig").Tun,
    else => @compileError("zunnel-proxy supports Linux and Windows only"),
};

/// Runs a helper command (ip / netsh), returning an error with its output on failure.
pub fn runCommand(gpa: std.mem.Allocator, argv: []const []const u8) !void {
    const res = std.process.Child.run(.{ .allocator = gpa, .argv = argv }) catch |err| {
        std.log.err("failed to run {s}: {s}", .{ argv[0], @errorName(err) });
        return err;
    };
    defer gpa.free(res.stdout);
    defer gpa.free(res.stderr);
    const ok = switch (res.term) {
        .Exited => |code| code == 0,
        else => false,
    };
    if (!ok) {
        const out = std.mem.trim(u8, if (res.stderr.len > 0) res.stderr else res.stdout, " \r\n");
        std.log.err("'{s}' failed: {s}", .{ try std.mem.join(gpa, " ", argv), out });
        return error.CommandFailed;
    }
}

/// Validates an IPv4 CIDR such as 10.0.0.0/24.
pub fn validateCidr(cidr: []const u8) bool {
    _ = Cidr.parse(cidr) catch return false;
    return true;
}

pub const Cidr = struct {
    net: u32,
    mask: u32,

    pub fn parse(text: []const u8) error{InvalidCidr}!Cidr {
        const slash = std.mem.indexOfScalar(u8, text, '/') orelse return error.InvalidCidr;
        const ip = std.net.Ip4Address.parse(text[0..slash], 0) catch return error.InvalidCidr;
        const bits = std.fmt.parseInt(u6, text[slash + 1 ..], 10) catch return error.InvalidCidr;
        if (bits > 32) return error.InvalidCidr;
        const mask: u32 = if (bits == 0) 0 else ~@as(u32, 0) << @intCast(32 - bits);
        const addr = std.mem.readInt(u32, std.mem.asBytes(&ip.sa.addr), .big);
        return .{ .net = addr & mask, .mask = mask };
    }

    pub fn contains(self: Cidr, ip: [4]u8) bool {
        return std.mem.readInt(u32, &ip, .big) & self.mask == self.net;
    }
};

test Cidr {
    const c = try Cidr.parse("240.0.0.0/4");
    try std.testing.expect(c.contains(.{ 240, 0, 0, 1 }));
    try std.testing.expect(c.contains(.{ 255, 1, 2, 3 }));
    try std.testing.expect(!c.contains(.{ 10, 0, 0, 1 }));
    try std.testing.expect((try Cidr.parse("0.0.0.0/0")).contains(.{ 1, 2, 3, 4 }));
}
