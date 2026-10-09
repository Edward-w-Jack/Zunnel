//! Windows TUN via Wintun (https://www.wintun.net). wintun.dll must sit next to
//! zunnel-proxy.exe (or in System32), and the proxy must run as Administrator.
const std = @import("std");
const tun = @import("tun.zig");
const windows = std.os.windows;

const WINAPI = std.builtin.CallingConvention.winapi;
const HANDLE = windows.HANDLE;
const Adapter = opaque {};
const Session = opaque {};

const ERROR_NO_MORE_ITEMS = 259;
const ERROR_HANDLE_EOF = 38;
const WAIT_OBJECT_0 = 0;
const LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200;
const LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;
const ring_capacity = 0x400000; // 4 MiB

extern "kernel32" fn LoadLibraryExW(name: [*:0]const u16, file: ?HANDLE, flags: u32) callconv(WINAPI) ?windows.HMODULE;
extern "kernel32" fn GetProcAddress(module: windows.HMODULE, name: [*:0]const u8) callconv(WINAPI) ?*const anyopaque;
extern "kernel32" fn GetLastError() callconv(WINAPI) u32;
extern "kernel32" fn WaitForSingleObject(h: HANDLE, ms: u32) callconv(WINAPI) u32;

const Api = struct {
    WintunCreateAdapter: *const fn ([*:0]const u16, [*:0]const u16, ?*const windows.GUID) callconv(WINAPI) ?*Adapter,
    WintunOpenAdapter: *const fn ([*:0]const u16) callconv(WINAPI) ?*Adapter,
    WintunCloseAdapter: *const fn (*Adapter) callconv(WINAPI) void,
    WintunStartSession: *const fn (*Adapter, u32) callconv(WINAPI) ?*Session,
    WintunEndSession: *const fn (*Session) callconv(WINAPI) void,
    WintunGetReadWaitEvent: *const fn (*Session) callconv(WINAPI) HANDLE,
    WintunReceivePacket: *const fn (*Session, *u32) callconv(WINAPI) ?[*]u8,
    WintunReleaseReceivePacket: *const fn (*Session, [*]const u8) callconv(WINAPI) void,
    WintunAllocateSendPacket: *const fn (*Session, u32) callconv(WINAPI) ?[*]u8,
    WintunSendPacket: *const fn (*Session, [*]const u8) callconv(WINAPI) void,

    fn load() !Api {
        const dll = std.unicode.utf8ToUtf16LeStringLiteral("wintun.dll");
        const module = LoadLibraryExW(dll, null, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32) orelse {
            std.log.err("wintun.dll not found; download it from https://www.wintun.net and place it next to zunnel-proxy.exe", .{});
            return error.WintunNotFound;
        };
        var api: Api = undefined;
        inline for (@typeInfo(Api).@"struct".fields) |f| {
            const sym = GetProcAddress(module, f.name ++ "") orelse return error.WintunSymbolMissing;
            @field(api, f.name) = @ptrCast(@alignCast(sym));
        }
        return api;
    }
};

pub const Tun = struct {
    gpa: std.mem.Allocator,
    api: Api,
    adapter: *Adapter,
    session: *Session,
    event: HANDLE,
    name: []const u8,

    pub fn open(gpa: std.mem.Allocator, name: []const u8, index: u8) !Tun {
        const api = try Api.load();
        const wname = try std.unicode.utf8ToUtf16LeAllocZ(gpa, name);
        defer gpa.free(wname);

        const adapter = api.WintunOpenAdapter(wname) orelse
            api.WintunCreateAdapter(wname, std.unicode.utf8ToUtf16LeStringLiteral("zunnel"), null) orelse {
            std.log.err("WintunCreateAdapter failed (error {d}); is the proxy running as Administrator?", .{GetLastError()});
            return error.AdapterCreateFailed;
        };
        errdefer api.WintunCloseAdapter(adapter);
        const session = api.WintunStartSession(adapter, ring_capacity) orelse return error.SessionStartFailed;

        const self: Tun = .{
            .gpa = gpa,
            .api = api,
            .adapter = adapter,
            .session = session,
            .event = api.WintunGetReadWaitEvent(session),
            .name = try gpa.dupe(u8, name),
        };
        const mtu_arg = std.fmt.comptimePrint("mtu={d}", .{tun.mtu});
        const if_arg = try std.fmt.allocPrint(gpa, "interface={s}", .{name});
        defer gpa.free(if_arg);
        tun.runCommand(gpa, &.{ "netsh", "interface", "ipv4", "set", "subinterface", if_arg, mtu_arg, "store=active" }) catch
            std.log.warn("could not set MTU on {s}", .{name});
        // Without an IPv4 address Windows has no source address for routed traffic
        // and fails connects instantly until APIPA kicks in seconds later.
        const name_arg = try std.fmt.allocPrint(gpa, "name={s}", .{name});
        defer gpa.free(name_arg);
        const a = tun.localAddress(index);
        const addr_arg = try std.fmt.allocPrint(gpa, "address={d}.{d}.{d}.{d}", .{ a[0], a[1], a[2], a[3] });
        defer gpa.free(addr_arg);
        tun.runCommand(gpa, &.{ "netsh", "interface", "ipv4", "set", "address", name_arg, "source=static", addr_arg, "mask=255.255.255.255", "gateway=none", "store=active" }) catch
            std.log.warn("could not assign {s} to {s}", .{ addr_arg, name });

        // New adapters land in the Public firewall profile, which drops inbound
        // ICMP destination-unreachable. Allow it to this adapter's address only,
        // so closed UDP ports and unreachable hosts reach the operator's tools.
        self.firewallRule(.add, a) catch std.log.warn("could not add firewall rule for ICMP unreachable on {s}", .{name});
        return self;
    }

    fn firewallRule(self: *const Tun, op: enum { add, delete }, a: [4]u8) !void {
        const rule = try std.fmt.allocPrint(self.gpa, "name=zunnel-{s}-icmp-unreachable", .{self.name});
        defer self.gpa.free(rule);
        // Delete first so a leftover rule from a crashed run is replaced, not duplicated.
        tun.runCommandQuiet(self.gpa, &.{ "netsh", "advfirewall", "firewall", "delete", "rule", rule });
        if (op == .delete) return;
        const localip = try std.fmt.allocPrint(self.gpa, "localip={d}.{d}.{d}.{d}", .{ a[0], a[1], a[2], a[3] });
        defer self.gpa.free(localip);
        try tun.runCommand(self.gpa, &.{ "netsh", "advfirewall", "firewall", "add", "rule", rule, "dir=in", "action=allow", "protocol=icmpv4:3,any", localip });
    }

    pub fn read(self: *Tun, buf: []u8) !usize {
        var size: u32 = 0;
        if (self.api.WintunReceivePacket(self.session, &size)) |pkt| {
            defer self.api.WintunReleaseReceivePacket(self.session, pkt);
            const n = @min(size, buf.len);
            @memcpy(buf[0..n], pkt[0..n]);
            return n;
        }
        switch (GetLastError()) {
            ERROR_NO_MORE_ITEMS => {
                _ = WaitForSingleObject(self.event, 500);
                return 0;
            },
            ERROR_HANDLE_EOF => return error.SessionEnded,
            else => return error.ReadFailed,
        }
    }

    pub fn write(self: *Tun, pkt: []const u8) void {
        const out = self.api.WintunAllocateSendPacket(self.session, @intCast(pkt.len)) orelse return;
        @memcpy(out[0..pkt.len], pkt);
        self.api.WintunSendPacket(self.session, out);
    }

    pub fn addRoute(self: *Tun, cidr: []const u8) !void {
        try self.route("add", cidr);
    }

    pub fn delRoute(self: *Tun, cidr: []const u8) !void {
        try self.route("delete", cidr);
    }

    fn route(self: *Tun, verb: []const u8, cidr: []const u8) !void {
        const prefix = try std.fmt.allocPrint(self.gpa, "prefix={s}", .{cidr});
        defer self.gpa.free(prefix);
        const iface = try std.fmt.allocPrint(self.gpa, "interface={s}", .{self.name});
        defer self.gpa.free(iface);
        try tun.runCommand(self.gpa, &.{ "netsh", "interface", "ipv4", verb, "route", prefix, iface, "nexthop=0.0.0.0", "store=active" });
    }

    pub fn close(self: *Tun) void {
        self.firewallRule(.delete, undefined) catch {};
        self.api.WintunEndSession(self.session);
        self.api.WintunCloseAdapter(self.adapter);
        self.gpa.free(self.name);
    }
};
