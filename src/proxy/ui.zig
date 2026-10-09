//! Operator-facing output: timestamped events and log lines on the console,
//! optionally mirrored to a log file (`-log`).
//!
//! While the operator is typing (interactive console), output from other
//! threads clears the input line, prints, and redraws the prompt and the
//! partly typed command, so the two never get mixed up.
const std = @import("std");
const common = @import("common");
const lineedit = @import("lineedit.zig");

const logfmt = common.logfmt;

/// Runtime log level (`-v` = debug, default info, `-q` = warnings only).
pub var level: std.log.Level = .info;

/// The console's terminal mode (raw while the line editor runs).
pub var terminal: lineedit.Terminal = .{};

var file_mutex: std.Thread.Mutex = .{};
var log_file: ?std.fs.File = null;

// The input line currently on screen, guarded by `term_mutex`.
var term_mutex: std.Thread.Mutex = .{};
var line_active = false;
var line_prompt: []const u8 = "";
var line_text: [lineedit.max_line]u8 = undefined;
var line_len: usize = 0;
var line_cursor: usize = 0;

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

fn writeStderr(text: []const u8) void {
    std.fs.File.stderr().writeAll(text) catch {};
}

fn drawLineLocked() void {
    var buf: [lineedit.max_line + 64]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    w.writeAll("\r\x1b[2K") catch {};
    w.writeAll(line_prompt) catch {};
    w.writeAll(line_text[0..line_len]) catch {};
    if (line_cursor < line_len) w.print("\x1b[{d}D", .{line_len - line_cursor}) catch {};
    writeStderr(w.buffered());
}

/// Shows (or updates) the input line being edited.
pub fn showLine(prompt: []const u8, text: []const u8, cursor: usize) void {
    term_mutex.lock();
    defer term_mutex.unlock();
    line_active = true;
    line_prompt = prompt;
    line_len = @min(text.len, line_text.len);
    @memcpy(line_text[0..line_len], text[0..line_len]);
    line_cursor = @min(cursor, line_len);
    drawLineLocked();
}

/// The line was submitted: leave it on screen and stop redrawing it.
pub fn endLine() void {
    term_mutex.lock();
    defer term_mutex.unlock();
    line_active = false;
    writeStderr("\n");
}

/// Prints `text` (complete lines) without disturbing the input line.
pub fn out(text: []const u8) void {
    term_mutex.lock();
    defer term_mutex.unlock();
    if (line_active) writeStderr("\r\x1b[2K") else writeStderr("\n");
    writeStderr(text);
    if (line_active) drawLineLocked();
}

/// Something the operator should see happen (an agent joined, a route was
/// added, ...): printed with a time and written to the log file.
pub fn event(comptime format: []const u8, args: anytype) void {
    var buf: [2048]u8 = undefined;
    const stamp = logfmt.now();
    const msg = std.fmt.bufPrint(&buf, format, args) catch buf[0..];
    var screen_buf: [2100]u8 = undefined;
    // stamp[11..19] is HH:MM:SS; the file gets the full date.
    out(std.fmt.bufPrint(&screen_buf, "[{s}] {s}\n", .{ stamp[11..19], msg }) catch return);
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
    out(text);
    toFile(text);
}

/// Puts the terminal back to normal; call before the process exits.
pub fn restoreTerminal() void {
    term_mutex.lock();
    defer term_mutex.unlock();
    if (line_active) writeStderr("\n");
    line_active = false;
    terminal.restore();
}
