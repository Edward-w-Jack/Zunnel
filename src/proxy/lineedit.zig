//! A small line editor for the proxy console: cursor movement, editing keys,
//! history and tab completion. `Editor` is pure (bytes in, actions out) so it
//! can be unit-tested; `Terminal` switches the console into raw mode.
const std = @import("std");
const builtin = @import("builtin");

pub const max_line = 512;

pub const Action = enum {
    /// Nothing visible changed.
    none,
    /// The line or cursor changed; redraw it.
    redraw,
    /// Enter: the line in `buf[0..len]` is complete.
    submit,
    /// Ctrl-D on an empty line.
    eof,
    /// Tab: the caller should offer completions for `beforeCursor()`.
    complete,
    /// Ctrl-L.
    clear_screen,
};

pub const Editor = struct {
    gpa: std.mem.Allocator,
    buf: [max_line]u8 = undefined,
    len: usize = 0,
    cursor: usize = 0,
    history: std.ArrayList([]u8) = .empty,
    /// Index into `history` while browsing with up/down; null = editing a new line.
    hist_pos: ?usize = null,
    /// The unfinished line saved while browsing history.
    draft: [max_line]u8 = undefined,
    draft_len: usize = 0,
    esc: enum { none, esc, csi, ss3 } = .none,
    csi_param: u8 = 0,
    last_was_cr: bool = false,

    pub const history_limit = 500;

    pub fn deinit(self: *Editor) void {
        for (self.history.items) |h| self.gpa.free(h);
        self.history.deinit(self.gpa);
    }

    pub fn line(self: *const Editor) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn beforeCursor(self: *const Editor) []const u8 {
        return self.buf[0..self.cursor];
    }

    pub fn reset(self: *Editor) void {
        self.len = 0;
        self.cursor = 0;
        self.hist_pos = null;
        self.esc = .none;
    }

    /// Adds a submitted line to the history (skipping blanks and repeats).
    pub fn remember(self: *Editor, text: []const u8) void {
        const t = std.mem.trim(u8, text, " \t");
        if (t.len == 0) return;
        if (self.history.items.len > 0 and std.mem.eql(u8, self.history.items[self.history.items.len - 1], t)) return;
        const copy = self.gpa.dupe(u8, t) catch return;
        if (self.history.items.len >= history_limit) self.gpa.free(self.history.orderedRemove(0));
        self.history.append(self.gpa, copy) catch self.gpa.free(copy);
    }

    pub fn feed(self: *Editor, c: u8) Action {
        switch (self.esc) {
            .esc => {
                self.esc = switch (c) {
                    '[' => .csi,
                    'O' => .ss3,
                    else => .none,
                };
                self.csi_param = 0;
                return .none;
            },
            .ss3 => {
                self.esc = .none;
                return switch (c) {
                    'H' => self.home(),
                    'F' => self.end(),
                    'A' => self.historyUp(),
                    'B' => self.historyDown(),
                    'C' => self.right(),
                    'D' => self.left(),
                    else => .none,
                };
            },
            .csi => {
                if (c >= '0' and c <= '9') {
                    self.csi_param = self.csi_param *% 10 +% (c - '0');
                    return .none;
                }
                if (c == ';') return .none;
                self.esc = .none;
                return switch (c) {
                    'A' => self.historyUp(),
                    'B' => self.historyDown(),
                    'C' => self.right(),
                    'D' => self.left(),
                    'H' => self.home(),
                    'F' => self.end(),
                    '~' => switch (self.csi_param) {
                        1, 7 => self.home(),
                        4, 8 => self.end(),
                        3 => self.deleteForward(),
                        else => .none,
                    },
                    else => .none,
                };
            },
            .none => {},
        }

        const was_cr = self.last_was_cr;
        self.last_was_cr = c == '\r';
        return switch (c) {
            0x1b => blk: {
                self.esc = .esc;
                break :blk .none;
            },
            '\r' => .submit,
            '\n' => if (was_cr) .none else .submit, // CR LF counts once
            '\t' => .complete,
            0x7f, 0x08 => self.backspace(),
            0x01 => self.home(), // Ctrl-A
            0x05 => self.end(), // Ctrl-E
            0x02 => self.left(), // Ctrl-B
            0x06 => self.right(), // Ctrl-F
            0x0b => blk: { // Ctrl-K: kill to end
                self.len = self.cursor;
                break :blk .redraw;
            },
            0x15 => blk: { // Ctrl-U: kill to start
                self.deleteRange(0, self.cursor);
                break :blk .redraw;
            },
            0x17 => self.deleteWordBack(), // Ctrl-W
            0x0c => .clear_screen, // Ctrl-L
            0x04 => if (self.len == 0) .eof else self.deleteForward(), // Ctrl-D
            0x10 => self.historyUp(), // Ctrl-P
            0x0e => self.historyDown(), // Ctrl-N
            else => if (c >= 0x20 and c < 0x7f) self.insert(&.{c}) else .none,
        };
    }

    pub fn insert(self: *Editor, text: []const u8) Action {
        if (self.len + text.len > self.buf.len) return .none;
        std.mem.copyBackwards(u8, self.buf[self.cursor + text.len .. self.len + text.len], self.buf[self.cursor..self.len]);
        @memcpy(self.buf[self.cursor..][0..text.len], text);
        self.len += text.len;
        self.cursor += text.len;
        return .redraw;
    }

    fn deleteRange(self: *Editor, from: usize, to: usize) void {
        std.mem.copyForwards(u8, self.buf[from..], self.buf[to..self.len]);
        self.len -= to - from;
        self.cursor = from;
    }

    fn backspace(self: *Editor) Action {
        if (self.cursor == 0) return .none;
        self.deleteRange(self.cursor - 1, self.cursor);
        return .redraw;
    }

    fn deleteForward(self: *Editor) Action {
        if (self.cursor == self.len) return .none;
        const at = self.cursor;
        self.deleteRange(at, at + 1);
        self.cursor = at;
        return .redraw;
    }

    fn deleteWordBack(self: *Editor) Action {
        var i = self.cursor;
        while (i > 0 and self.buf[i - 1] == ' ') i -= 1;
        while (i > 0 and self.buf[i - 1] != ' ') i -= 1;
        if (i == self.cursor) return .none;
        self.deleteRange(i, self.cursor);
        return .redraw;
    }

    fn left(self: *Editor) Action {
        if (self.cursor == 0) return .none;
        self.cursor -= 1;
        return .redraw;
    }

    fn right(self: *Editor) Action {
        if (self.cursor == self.len) return .none;
        self.cursor += 1;
        return .redraw;
    }

    fn home(self: *Editor) Action {
        self.cursor = 0;
        return .redraw;
    }

    fn end(self: *Editor) Action {
        self.cursor = self.len;
        return .redraw;
    }

    fn setLine(self: *Editor, text: []const u8) void {
        const n = @min(text.len, self.buf.len);
        @memcpy(self.buf[0..n], text[0..n]);
        self.len = n;
        self.cursor = n;
    }

    fn historyUp(self: *Editor) Action {
        const h = self.history.items;
        if (h.len == 0) return .none;
        const pos = if (self.hist_pos) |p| (if (p == 0) return .none else p - 1) else blk: {
            @memcpy(self.draft[0..self.len], self.buf[0..self.len]);
            self.draft_len = self.len;
            break :blk h.len - 1;
        };
        self.hist_pos = pos;
        self.setLine(h[pos]);
        return .redraw;
    }

    fn historyDown(self: *Editor) Action {
        const p = self.hist_pos orelse return .none;
        if (p + 1 < self.history.items.len) {
            self.hist_pos = p + 1;
            self.setLine(self.history.items[p + 1]);
        } else {
            self.hist_pos = null;
            self.setLine(self.draft[0..self.draft_len]);
        }
        return .redraw;
    }

    /// Applies completions for the word before the cursor: a single match is
    /// completed (plus a space); several are extended to their common prefix.
    /// Returns true if several candidates remain and should be listed.
    pub fn applyCompletion(self: *Editor, candidates: []const []const u8) bool {
        if (candidates.len == 0) return false;
        const before = self.beforeCursor();
        const word_start = if (std.mem.lastIndexOfScalar(u8, before, ' ')) |i| i + 1 else 0;
        const typed = before[word_start..];
        var common = candidates[0];
        for (candidates[1..]) |c| {
            var n: usize = 0;
            while (n < common.len and n < c.len and common[n] == c[n]) n += 1;
            common = common[0..n];
        }
        if (common.len > typed.len) _ = self.insert(common[typed.len..]);
        if (candidates.len == 1) {
            if (self.cursor == self.len) _ = self.insert(" ");
            return false;
        }
        return true;
    }
};

// ------------------------------------------------------------------ terminal

/// Puts the console into raw (character-at-a-time, no echo) mode and back.
pub const Terminal = struct {
    saved: Saved = undefined,
    active: bool = false,

    const Saved = switch (builtin.os.tag) {
        .windows => struct { in_mode: u32, out_mode: u32 },
        else => std.posix.termios,
    };

    const win = struct {
        const ENABLE_PROCESSED_INPUT = 0x0001;
        const ENABLE_LINE_INPUT = 0x0002;
        const ENABLE_ECHO_INPUT = 0x0004;
        const ENABLE_VIRTUAL_TERMINAL_INPUT = 0x0200;
        const ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;
        extern "kernel32" fn GetConsoleMode(h: std.os.windows.HANDLE, mode: *u32) callconv(.winapi) std.os.windows.BOOL;
        extern "kernel32" fn SetConsoleMode(h: std.os.windows.HANDLE, mode: u32) callconv(.winapi) std.os.windows.BOOL;
    };

    /// True when stdin is an interactive terminal (not a pipe or file).
    pub fn interactive() bool {
        return std.fs.File.stdin().isTty() and std.fs.File.stderr().isTty();
    }

    pub fn enterRaw(self: *Terminal) bool {
        const in = std.fs.File.stdin().handle;
        if (builtin.os.tag == .windows) {
            const out = std.fs.File.stderr().handle;
            var in_mode: u32 = 0;
            var out_mode: u32 = 0;
            if (win.GetConsoleMode(in, &in_mode) == 0 or win.GetConsoleMode(out, &out_mode) == 0) return false;
            self.saved = .{ .in_mode = in_mode, .out_mode = out_mode };
            // Keep Ctrl-C delivered as a signal (graceful shutdown).
            const raw_in = (in_mode & ~@as(u32, win.ENABLE_LINE_INPUT | win.ENABLE_ECHO_INPUT)) | win.ENABLE_VIRTUAL_TERMINAL_INPUT | win.ENABLE_PROCESSED_INPUT;
            if (win.SetConsoleMode(in, raw_in) == 0) return false;
            _ = win.SetConsoleMode(out, out_mode | win.ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        } else {
            const t = std.posix.tcgetattr(in) catch return false;
            self.saved = t;
            var raw = t;
            raw.lflag.ICANON = false;
            raw.lflag.ECHO = false;
            raw.cc[@intFromEnum(std.posix.V.MIN)] = 1;
            raw.cc[@intFromEnum(std.posix.V.TIME)] = 0;
            std.posix.tcsetattr(in, .NOW, raw) catch return false;
        }
        self.active = true;
        return true;
    }

    pub fn restore(self: *Terminal) void {
        if (!self.active) return;
        self.active = false;
        const in = std.fs.File.stdin().handle;
        if (builtin.os.tag == .windows) {
            _ = win.SetConsoleMode(in, self.saved.in_mode);
            _ = win.SetConsoleMode(std.fs.File.stderr().handle, self.saved.out_mode);
        } else {
            std.posix.tcsetattr(in, .NOW, self.saved) catch {};
        }
    }

    /// Reads one byte of input; null at end of input.
    pub fn readByte() ?u8 {
        var b: [1]u8 = undefined;
        const n = std.fs.File.stdin().read(&b) catch return null;
        return if (n == 0) null else b[0];
    }
};

// --------------------------------------------------------------------- tests

fn feedAll(e: *Editor, bytes: []const u8) Action {
    var last: Action = .none;
    for (bytes) |b| last = e.feed(b);
    return last;
}

test "typing, cursor movement and editing keys" {
    var e: Editor = .{ .gpa = std.testing.allocator };
    defer e.deinit();
    _ = feedAll(&e, "route add 10.0.0.0/24");
    try std.testing.expectEqualStrings("route add 10.0.0.0/24", e.line());
    _ = feedAll(&e, "\x1b[D\x1b[D"); // left x2: cursor between '/' and '2'
    _ = feedAll(&e, "\x7f"); // backspace removes '/'
    try std.testing.expectEqualStrings("route add 10.0.0.024", e.line());
    _ = feedAll(&e, "\x01"); // Ctrl-A
    try std.testing.expectEqual(@as(usize, 0), e.cursor);
    _ = feedAll(&e, "\x1b[3~"); // Delete
    try std.testing.expectEqualStrings("oute add 10.0.0.024", e.line());
    _ = feedAll(&e, "\x05\x17"); // Ctrl-E, Ctrl-W deletes the last word
    try std.testing.expectEqualStrings("oute add ", e.line());
    _ = feedAll(&e, "\x15"); // Ctrl-U
    try std.testing.expectEqualStrings("", e.line());
    try std.testing.expectEqual(Action.eof, e.feed(0x04));
    _ = feedAll(&e, "ls");
    try std.testing.expectEqual(Action.submit, e.feed('\r'));
    try std.testing.expectEqual(Action.none, e.feed('\n')); // CR LF counts once
}

test "history browsing keeps the draft" {
    var e: Editor = .{ .gpa = std.testing.allocator };
    defer e.deinit();
    e.remember("sessions");
    e.remember("ifaces");
    e.remember("ifaces"); // repeat ignored
    _ = feedAll(&e, "draft");
    _ = feedAll(&e, "\x1b[A");
    try std.testing.expectEqualStrings("ifaces", e.line());
    _ = feedAll(&e, "\x1b[A\x1b[A"); // stops at the oldest
    try std.testing.expectEqualStrings("sessions", e.line());
    _ = feedAll(&e, "\x1b[B\x1b[B");
    try std.testing.expectEqualStrings("draft", e.line());
}

test "completion" {
    var e: Editor = .{ .gpa = std.testing.allocator };
    defer e.deinit();
    _ = feedAll(&e, "ses");
    try std.testing.expectEqual(Action.complete, e.feed('\t'));
    try std.testing.expect(!e.applyCompletion(&.{"sessions"}));
    try std.testing.expectEqualStrings("sessions ", e.line());

    e.reset();
    _ = feedAll(&e, "li");
    try std.testing.expect(e.applyCompletion(&.{ "listener", "listeners" }));
    try std.testing.expectEqualStrings("listener", e.line());
}
