//! Monotonic time for timeouts and durations. `std.time.milliTimestamp`
//! follows the wall clock, which jumps when the system time is set (an NTP
//! correction, a VM resuming): a timeout measured with it can fire at once or
//! not for hours. Wall-clock time is only for real dates: log stamps and
//! `-expire` deadlines.
const std = @import("std");

var origin: ?std.time.Instant = null;
var origin_once = std.once(setOrigin);

fn setOrigin() void {
    origin = std.time.Instant.now() catch null;
}

/// Milliseconds since an arbitrary point early in the process's life. Never
/// affected by changes to the system time. Only differences are meaningful.
pub fn monotonicMs() i64 {
    origin_once.call();
    // Instant is unsupported only on targets without any monotonic clock.
    const start = origin orelse return std.time.milliTimestamp();
    const now = std.time.Instant.now() catch return std.time.milliTimestamp();
    // `since` traps if `now` is earlier, which a buggy clock could produce.
    if (now.order(start) == .lt) return 0;
    return @intCast(now.since(start) / std.time.ns_per_ms);
}

test monotonicMs {
    const a = monotonicMs();
    std.Thread.sleep(30 * std.time.ns_per_ms);
    const b = monotonicMs();
    try std.testing.expect(b - a >= 20);
    try std.testing.expect(monotonicMs() >= b);
}
