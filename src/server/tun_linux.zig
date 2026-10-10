const std = @import("std");
const tun = @import("tun.zig");
const posix = std.posix;
const linux = std.os.linux;

const IFF_TUN = 0x0001;
const IFF_NO_PI = 0x1000;
const TUNSETIFF = 0x400454ca;

pub const Tun = struct {
    gpa: std.mem.Allocator,
    fd: posix.fd_t,
    name: []const u8,

    /// Opens (or creates) the TUN interface. Creating needs CAP_NET_ADMIN, but a
    /// persistent interface owned by the current user can be opened without it:
    ///   sudo ip tuntap add user $USER mode tun zunnel
    pub fn open(gpa: std.mem.Allocator, name: []const u8, index: u8) !Tun {
        _ = index;
        if (name.len == 0 or name.len >= 16) return error.InvalidName;
        const fd = try posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
        errdefer posix.close(fd);

        var ifr = extern struct { name: [16]u8, flags: u16, pad: [22]u8 }{
            .name = [_]u8{0} ** 16,
            .flags = IFF_TUN | IFF_NO_PI,
            .pad = [_]u8{0} ** 22,
        };
        @memcpy(ifr.name[0..name.len], name);
        switch (posix.errno(linux.ioctl(fd, TUNSETIFF, @intFromPtr(&ifr)))) {
            .SUCCESS => {},
            .PERM, .ACCES => return error.AccessDenied,
            .BUSY => return error.InterfaceBusy,
            else => |e| return posix.unexpectedErrno(e),
        }

        const self: Tun = .{ .gpa = gpa, .fd = fd, .name = try gpa.dupe(u8, name) };
        const mtu_s = std.fmt.comptimePrint("{d}", .{tun.mtu});
        tun.runCommand(gpa, &.{ "ip", "link", "set", "dev", name, "mtu", mtu_s, "up" }) catch
            std.log.warn("could not bring {s} up; run: ip link set dev {s} up", .{ name, name });
        return self;
    }

    pub fn read(self: *Tun, buf: []u8) !usize {
        var fds = [_]posix.pollfd{.{ .fd = self.fd, .events = posix.POLL.IN, .revents = 0 }};
        if (try posix.poll(&fds, 500) == 0) return 0;
        return posix.read(self.fd, buf) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => err,
        };
    }

    pub fn write(self: *Tun, pkt: []const u8) void {
        _ = posix.write(self.fd, pkt) catch {};
    }

    pub fn addRoute(self: *Tun, cidr: []const u8) !void {
        try tun.runCommand(self.gpa, &.{ "ip", "route", "replace", cidr, "dev", self.name });
    }

    pub fn delRoute(self: *Tun, cidr: []const u8) !void {
        try tun.runCommand(self.gpa, &.{ "ip", "route", "del", cidr, "dev", self.name });
    }

    pub fn close(self: *Tun) void {
        posix.close(self.fd);
        self.gpa.free(self.name);
    }
};
