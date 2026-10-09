//! Operator-facing output: timestamped events and log lines on the console,
//! optionally mirrored to a log file (`-log`).
const std = @import("std");
const common = @import("common");

const logfmt = common.logfmt;

/// Runtime log level (`-v` = debug, default info, `-q` = warnings only).
pub var level: std.log.Level = .info;

var file_mutex: std.Thread.Mutex = .{};
var log_file: ?std.fs.File = null;

/// Appends all events and log lines to `path` (created if missing).
pub fn openLog(path: []const u8) !void {
    const f = try std.fs.cwd().createFile(path, .{ .truncate = false });
    errdefer f.close();
    try f.seekFromEnd(0);
    file_mutex.lock();
    defer file_mutex.unlock();
    log_file = f;
    var stamp = logfmt.now();
    f.writeAll("--- zunnel proxy started ") catch {};
    f.writeAll(&stamp) catch {};
    f.writeAll(" ---\n") catch {};
}

fn toFile(text: []const u8) void {
    file_mutex.lock();
    defer file_mutex.unlock();
    if (log_file) |f| f.writeAll(text) catch {};
}

/// Something the operator should see happen (an agent joined, a route was
/// added, ...): printed with a time and written to the log file.
pub fn event(comptime format: []const u8, args: anytype) void {
    var buf: [2048]u8 = undefined;
    const stamp = logfmt.now();
    const msg = std.fmt.bufPrint(&buf, format, args) catch buf[0..];
    // stamp[11..19] is HH:MM:SS; the file gets the full date.
    std.debug.print("\n[{s}] {s}\n", .{ stamp[11..19], msg });
    var line_buf: [2100]u8 = undefined;
    toFile(std.fmt.bufPrint(&line_buf, "{s} {s}\n", .{ &stamp, msg }) catch return);
}

/// `std_options.logFn` for the proxy.
pub fn logFn(
    comptime message_level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(message_level) > @intFromEnum(level)) return;
    var buf: [2048]u8 = undefined;
    const text = logfmt.line(&buf, message_level, scope, format, args);
    std.debug.print("{s}", .{text});
    toFile(text);
}
