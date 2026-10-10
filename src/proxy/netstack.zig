//! The single lwIP instance shared by all tunnels: global lock, timers, and
//! the C hooks lwIP calls back into.
const std = @import("std");
const lwip = @import("lwip.zig");
const Tunnel = @import("tunnel.zig").Tunnel;

const c = lwip.c;
const clock = @import("common").clock;

/// Serialises every lwIP call and all tunnel flow state.
/// Lock order: Server.mutex -> netstack.lock -> Link.mutex.
pub var lock: std.Thread.Mutex = .{};

var started = false;
/// Tunnels swept by the timer thread (guarded by `lock`).
var tunnels: std.ArrayList(*Tunnel) = .empty;
var gpa_: std.mem.Allocator = undefined;

/// Initialises lwIP and starts the timer thread (idempotent).
pub fn start(gpa: std.mem.Allocator) !void {
    lock.lock();
    defer lock.unlock();
    if (started) return;
    gpa_ = gpa;
    c.lwip_init();
    (try std.Thread.spawn(.{}, timerLoop, .{})).detach();
    started = true;
}

/// Caller holds `lock`.
pub fn register(t: *Tunnel) !void {
    try tunnels.append(gpa_, t);
}

/// Caller holds `lock`.
pub fn unregister(t: *Tunnel) void {
    for (tunnels.items, 0..) |x, i| if (x == t) {
        _ = tunnels.swapRemove(i);
        return;
    };
}

fn timerLoop() void {
    var last_sweep = clock.monotonicMs();
    while (true) {
        std.Thread.sleep(50 * std.time.ns_per_ms);
        lock.lock();
        defer lock.unlock();
        c.sys_check_timeouts();
        const now = clock.monotonicMs();
        if (now - last_sweep >= 1000) {
            last_sweep = now;
            for (tunnels.items) |t| t.sweepLocked(now);
        }
    }
}

// ------------------------------------------------------------------ C hooks

/// lwIP's clock for TCP timers; monotonic so retransmit and TIME_WAIT timers
/// are not thrown off when the system time is set. Wraps at 2^32 like lwIP expects.
export fn sys_now() u32 {
    return @truncate(@as(u64, @bitCast(clock.monotonicMs())));
}

export fn zunnel_lwip_rand() c_uint {
    return std.crypto.random.int(c_uint);
}

export fn zunnel_lwip_assert(msg: [*:0]const u8, line: c_int, file: [*:0]const u8) void {
    std.debug.panic("lwIP assertion \"{s}\" failed at {s}:{d}", .{ msg, file, line });
}

/// LWIP_HOOK_IP4_ROUTE_SRC: while lwIP processes an input packet, unbound
/// output (e.g. a RST for an unknown connection) goes back out of the netif
/// the packet arrived on; otherwise lwIP falls back to its default netif.
export fn zunnel_route_src(src: ?*const anyopaque, dest: ?*const anyopaque) ?*c.struct_netif {
    _ = src;
    _ = dest;
    return c.ip_data.current_input_netif;
}
