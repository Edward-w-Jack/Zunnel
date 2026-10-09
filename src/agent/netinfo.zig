//! Lists the agent host's network interfaces for the proxy's `ifconfig`,
//! without privileges. Output is plain text, one item per line:
//!
//!     iface=<name> <addr>/<prefix> [<addr>/<prefix> ...]
//!     gateway=<addr> <iface>
//!
//! Windows: GetAdaptersAddresses. Linux: SIOCGIFCONF/SIOCGIFNETMASK for
//! IPv4, /proc/net/if_inet6 for IPv6, /proc/net/route for the gateway.
//! macOS: getifaddrs.
const std = @import("std");
const builtin = @import("builtin");

const Writer = std.Io.Writer;

pub fn write(gpa: std.mem.Allocator, w: *Writer) !void {
    switch (builtin.os.tag) {
        .windows => try writeWindows(gpa, w),
        .linux => try writeLinux(w),
        .macos => try writeDarwin(w),
        else => try w.writeAll("note=interface listing is not supported on this OS\n"),
    }
}

fn prefixLen(mask: []const u8) u8 {
    var n: u8 = 0;
    for (mask) |b| n += @popCount(b);
    return n;
}

fn writeAddr(w: *Writer, family: enum { v4, v6 }, bytes: []const u8, prefix: u8) !void {
    switch (family) {
        .v4 => try w.print(" {d}.{d}.{d}.{d}/{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3], prefix }),
        .v6 => {
            const a = std.net.Address.initIp6(bytes[0..16].*, 0, 0, 0);
            // Format as "[addr]:0" and strip the brackets/port.
            var buf: [64]u8 = undefined;
            const s = std.fmt.bufPrint(&buf, "{f}", .{a}) catch return;
            const end = std.mem.lastIndexOfScalar(u8, s, ']') orelse s.len;
            try w.print(" {s}/{d}", .{ std.mem.trimLeft(u8, s[0..end], "["), prefix });
        },
    }
}

// ------------------------------------------------------------------ Windows

const win = struct {
    const SOCKET_ADDRESS = extern struct { sockaddr: ?*std.os.windows.ws2_32.sockaddr, len: i32 };
    const UnicastAddress = extern struct {
        header: u64,
        next: ?*UnicastAddress,
        address: SOCKET_ADDRESS,
        prefix_origin: i32,
        suffix_origin: i32,
        dad_state: i32,
        valid_lifetime: u32,
        preferred_lifetime: u32,
        lease_lifetime: u32,
        on_link_prefix_length: u8,
    };
    const GatewayAddress = extern struct {
        header: u64,
        next: ?*GatewayAddress,
        address: SOCKET_ADDRESS,
    };
    /// IP_ADAPTER_ADDRESSES_LH, up to the fields we read.
    const AdapterAddresses = extern struct {
        header: u64,
        next: ?*AdapterAddresses,
        adapter_name: ?[*:0]u8,
        first_unicast: ?*UnicastAddress,
        first_anycast: ?*anyopaque,
        first_multicast: ?*anyopaque,
        first_dns_server: ?*anyopaque,
        dns_suffix: ?[*:0]u16,
        description: ?[*:0]u16,
        friendly_name: ?[*:0]u16,
        physical_address: [8]u8,
        physical_address_length: u32,
        flags: u32,
        mtu: u32,
        if_type: u32,
        oper_status: i32,
        ipv6_if_index: u32,
        zone_indices: [16]u32,
        first_prefix: ?*anyopaque,
        transmit_link_speed: u64,
        receive_link_speed: u64,
        first_wins_server: ?*anyopaque,
        first_gateway: ?*GatewayAddress,
    };
    const GAA_FLAG_SKIP_ANYCAST = 0x2;
    const GAA_FLAG_SKIP_MULTICAST = 0x4;
    const GAA_FLAG_SKIP_DNS_SERVER = 0x8;
    const GAA_FLAG_INCLUDE_GATEWAYS = 0x80;
    const ERROR_BUFFER_OVERFLOW = 111;
    const IF_OPER_STATUS_UP = 1;
    const IF_TYPE_SOFTWARE_LOOPBACK = 24;
    extern "iphlpapi" fn GetAdaptersAddresses(family: u32, flags: u32, reserved: ?*anyopaque, addresses: ?*AdapterAddresses, size: *u32) callconv(.winapi) u32;
};

fn writeWindows(gpa: std.mem.Allocator, w: *Writer) !void {
    const flags = win.GAA_FLAG_SKIP_ANYCAST | win.GAA_FLAG_SKIP_MULTICAST | win.GAA_FLAG_SKIP_DNS_SERVER | win.GAA_FLAG_INCLUDE_GATEWAYS;
    var size: u32 = 16 * 1024;
    var buf: []align(8) u8 = &.{};
    defer gpa.free(buf);
    var rc: u32 = win.ERROR_BUFFER_OVERFLOW;
    var tries: u8 = 0;
    while (rc == win.ERROR_BUFFER_OVERFLOW and tries < 3) : (tries += 1) {
        gpa.free(buf);
        buf = try gpa.alignedAlloc(u8, .@"8", size);
        rc = win.GetAdaptersAddresses(0, flags, null, @ptrCast(buf.ptr), &size);
    }
    if (rc != 0) return w.print("note=GetAdaptersAddresses failed ({d})\n", .{rc});

    var it: ?*win.AdapterAddresses = @ptrCast(buf.ptr);
    while (it) |a| : (it = a.next) {
        if (a.oper_status != win.IF_OPER_STATUS_UP or a.if_type == win.IF_TYPE_SOFTWARE_LOOPBACK) continue;
        var name_buf: [128]u8 = undefined;
        const name = if (a.friendly_name) |fname| blk: {
            const n = std.unicode.utf16LeToUtf8(&name_buf, std.mem.span(fname)) catch break :blk "?";
            break :blk name_buf[0..n];
        } else "?";
        try w.print("iface={s}", .{name});
        var u = a.first_unicast;
        while (u) |ua| : (u = ua.next) {
            const sa = ua.address.sockaddr orelse continue;
            switch (sa.family) {
                std.os.windows.ws2_32.AF.INET => {
                    const in: *const std.os.windows.ws2_32.sockaddr.in = @ptrCast(@alignCast(sa));
                    try writeAddr(w, .v4, std.mem.asBytes(&in.addr), ua.on_link_prefix_length);
                },
                std.os.windows.ws2_32.AF.INET6 => {
                    const in6: *const std.os.windows.ws2_32.sockaddr.in6 = @ptrCast(@alignCast(sa));
                    try writeAddr(w, .v6, &in6.addr, ua.on_link_prefix_length);
                },
                else => {},
            }
        }
        try w.writeAll("\n");
        var g = a.first_gateway;
        while (g) |ga| : (g = ga.next) {
            const sa = ga.address.sockaddr orelse continue;
            if (sa.family != std.os.windows.ws2_32.AF.INET) continue;
            const in: *const std.os.windows.ws2_32.sockaddr.in = @ptrCast(@alignCast(sa));
            const b = std.mem.asBytes(&in.addr);
            try w.print("gateway={d}.{d}.{d}.{d} {s}\n", .{ b[0], b[1], b[2], b[3], name });
        }
    }
}

// -------------------------------------------------------------------- Linux

fn writeLinux(w: *Writer) !void {
    const linux = std.os.linux;
    const fd = std.posix.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0) catch
        return w.writeAll("note=cannot open a socket to list interfaces\n");
    defer std.posix.close(fd);

    // Collect names from IPv4 (SIOCGIFCONF) and IPv6 (/proc/net/if_inet6),
    // then print one line per interface.
    var reqs: [64]linux.ifreq = undefined;
    const IfConf = extern struct { len: i32, buf: [*]linux.ifreq };
    var conf: IfConf = .{ .len = @sizeOf(@TypeOf(reqs)), .buf = &reqs };
    const n_v4: usize = switch (std.posix.errno(linux.ioctl(fd, linux.SIOCGIFCONF, @intFromPtr(&conf)))) {
        .SUCCESS => @as(usize, @intCast(conf.len)) / @sizeOf(linux.ifreq),
        else => 0,
    };

    var v6_buf: [16 * 1024]u8 = undefined;
    const v6 = std.fs.cwd().readFile("/proc/net/if_inet6", &v6_buf) catch "";

    var names: [64][linux.IFNAMESIZE]u8 = undefined;
    var name_count: usize = 0;
    const addName = struct {
        fn f(list: *[64][linux.IFNAMESIZE]u8, count: *usize, name: []const u8) void {
            for (list[0..count.*]) |*n| if (std.mem.eql(u8, std.mem.sliceTo(n, 0), name)) return;
            if (count.* == list.len or name.len >= linux.IFNAMESIZE) return;
            @memset(&list[count.*], 0);
            @memcpy(list[count.*][0..name.len], name);
            count.* += 1;
        }
    }.f;
    for (reqs[0..n_v4]) |*r| addName(&names, &name_count, std.mem.sliceTo(&r.ifrn.name, 0));
    var lines = std.mem.tokenizeScalar(u8, v6, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeAny(u8, line, " \t");
        var cols: [6][]const u8 = undefined;
        var i: usize = 0;
        while (f.next()) |c| : (i += 1) if (i < 6) {
            cols[i] = c;
        };
        if (i >= 6) addName(&names, &name_count, cols[5]);
    }

    for (names[0..name_count]) |*raw| {
        const name = std.mem.sliceTo(raw, 0);
        if (std.mem.eql(u8, name, "lo")) continue;
        try w.print("iface={s}", .{name});
        for (reqs[0..n_v4]) |*r| {
            if (!std.mem.eql(u8, std.mem.sliceTo(&r.ifrn.name, 0), name)) continue;
            const addr = std.mem.asBytes(&r.ifru.addr)[4..8];
            var mreq: linux.ifreq = r.*;
            const prefix: u8 = switch (std.posix.errno(linux.ioctl(fd, linux.SIOCGIFNETMASK, @intFromPtr(&mreq)))) {
                .SUCCESS => prefixLen(std.mem.asBytes(&mreq.ifru.netmask)[4..8]),
                else => 32,
            };
            try writeAddr(w, .v4, addr, prefix);
        }
        var l6 = std.mem.tokenizeScalar(u8, v6, '\n');
        while (l6.next()) |line| {
            var f = std.mem.tokenizeAny(u8, line, " \t");
            const hex = f.next() orelse continue;
            _ = f.next(); // ifindex
            const plen = f.next() orelse continue;
            _ = f.next(); // scope
            _ = f.next(); // flags
            const dev = f.next() orelse continue;
            if (!std.mem.eql(u8, dev, name) or hex.len != 32) continue;
            var bytes: [16]u8 = undefined;
            _ = std.fmt.hexToBytes(&bytes, hex) catch continue;
            try writeAddr(w, .v6, &bytes, std.fmt.parseInt(u8, plen, 16) catch 128);
        }
        try w.writeAll("\n");
    }

    // Default gateway: /proc/net/route rows with destination 00000000.
    var route_buf: [16 * 1024]u8 = undefined;
    const routes = std.fs.cwd().readFile("/proc/net/route", &route_buf) catch "";
    var rl = std.mem.tokenizeScalar(u8, routes, '\n');
    _ = rl.next(); // header
    while (rl.next()) |line| {
        var f = std.mem.tokenizeAny(u8, line, " \t");
        const dev = f.next() orelse continue;
        const dest = f.next() orelse continue;
        const gw = f.next() orelse continue;
        if (!std.mem.eql(u8, dest, "00000000")) continue;
        const g = std.fmt.parseInt(u32, gw, 16) catch continue;
        const b = std.mem.asBytes(&g); // little-endian hex of a network-order value
        try w.print("gateway={d}.{d}.{d}.{d} {s}\n", .{ b[0], b[1], b[2], b[3], dev });
    }
}

// -------------------------------------------------------------------- macOS

const darwin = struct {
    const ifaddrs = extern struct {
        next: ?*ifaddrs,
        name: [*:0]const u8,
        flags: c_uint,
        addr: ?*const std.c.sockaddr,
        netmask: ?*const std.c.sockaddr,
        dstaddr: ?*const std.c.sockaddr,
        data: ?*anyopaque,
    };
    extern "c" fn getifaddrs(out: *?*ifaddrs) c_int;
    extern "c" fn freeifaddrs(list: ?*ifaddrs) void;
    const IFF_UP = 0x1;
    const IFF_LOOPBACK = 0x8;
};

fn writeDarwin(w: *Writer) !void {
    var list: ?*darwin.ifaddrs = null;
    if (darwin.getifaddrs(&list) != 0) return w.writeAll("note=getifaddrs failed\n");
    defer darwin.freeifaddrs(list);

    var printed: [64][]const u8 = undefined;
    var n_printed: usize = 0;
    var outer = list;
    while (outer) |a| : (outer = a.next) {
        const name = std.mem.span(a.name);
        if (a.flags & darwin.IFF_UP == 0 or a.flags & darwin.IFF_LOOPBACK != 0) continue;
        const seen = for (printed[0..n_printed]) |p| {
            if (std.mem.eql(u8, p, name)) break true;
        } else false;
        if (seen or n_printed == printed.len) continue;
        printed[n_printed] = name;
        n_printed += 1;

        try w.print("iface={s}", .{name});
        var inner = list;
        while (inner) |b| : (inner = b.next) {
            if (!std.mem.eql(u8, std.mem.span(b.name), name)) continue;
            const sa = b.addr orelse continue;
            const mask = b.netmask;
            switch (sa.family) {
                std.c.AF.INET => {
                    const in: *const std.c.sockaddr.in = @ptrCast(@alignCast(sa));
                    const prefix: u8 = if (mask) |m| prefixLen(std.mem.asBytes(&@as(*const std.c.sockaddr.in, @ptrCast(@alignCast(m))).addr)) else 32;
                    try writeAddr(w, .v4, std.mem.asBytes(&in.addr), prefix);
                },
                std.c.AF.INET6 => {
                    const in6: *const std.c.sockaddr.in6 = @ptrCast(@alignCast(sa));
                    const prefix: u8 = if (mask) |m| prefixLen(&@as(*const std.c.sockaddr.in6, @ptrCast(@alignCast(m))).addr) else 128;
                    try writeAddr(w, .v6, &in6.addr, prefix);
                },
                else => {},
            }
        }
        try w.writeAll("\n");
    }
}

test "interface listing produces lines" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try write(std.testing.allocator, &out.writer);
    // Every line is key=value.
    var lines = std.mem.tokenizeScalar(u8, out.written(), '\n');
    while (lines.next()) |line| try std.testing.expect(std.mem.indexOfScalar(u8, line, '=') != null);
}
