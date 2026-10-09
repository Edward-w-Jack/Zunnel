//! Log formatting shared by the proxy and the agent: UTC timestamps
//! (`2026-10-09 14:07:00Z`) so logs from different machines line up.
const std = @import("std");

pub const Stamp = [20]u8;

/// `YYYY-MM-DD HH:MM:SSZ` for a Unix time in milliseconds.
pub fn timestamp(ms: i64) Stamp {
    const secs: u64 = @intCast(@max(0, @divFloor(ms, 1000)));
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const day = es.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    var out: Stamp = undefined;
    _ = std.fmt.bufPrint(&out, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,                 md.month.numeric(),          @as(u8, md.day_index) + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
    return out;
}

pub fn now() Stamp {
    return timestamp(std.time.milliTimestamp());
}

/// Formats one log line: `<stamp> <level>(<scope>): <message>\n`.
pub fn line(
    buf: []u8,
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) []const u8 {
    const stamp = now();
    const prefix = comptime level.asText() ++ if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    return std.fmt.bufPrint(buf, "{s} " ++ prefix ++ format ++ "\n", .{&stamp} ++ args) catch blk: {
        // Too long for the buffer: keep the start and mark the cut.
        const cut = buf.len - 5;
        @memcpy(buf[cut..], " ...\n");
        break :blk buf;
    };
}

test timestamp {
    // 2026-10-20T18:00:00Z
    try std.testing.expectEqualStrings("2026-10-20 18:00:00Z", &timestamp(1792519200000));
    try std.testing.expectEqualStrings("1970-01-01 00:00:00Z", &timestamp(0));
}
