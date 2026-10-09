//! Agent configuration, resolved from (highest precedence first):
//!   1. command-line flags
//!   2. environment variables (ZUNNEL_CONNECT, ZUNNEL_PUBKEY, ZUNNEL_SECRET,
//!      ZUNNEL_EXPIRE, ZUNNEL_ID)
//!   3. values baked in at build time (`zig build -Dagent-connect=... ...`)
//! An agent built with a baked config runs with no arguments at all, which is
//! also what a DLL build needs.
const std = @import("std");
const common = @import("common");

const keys = common.keys;
const proto = common.proto;

pub const Config = struct {
    host: []const u8,
    port: u16,
    /// null with `insecure` = accept any proxy key.
    pubkey: ?[32]u8,
    insecure: bool,
    secret: []const u8,
    retry: bool,
    /// Absolute deadline (Unix ms) after which the agent stops for good.
    expire_at_ms: ?i64,
    /// Overrides the host-derived identity.
    id: ?[]const u8,
};

/// One configuration source; null fields defer to lower-precedence sources.
pub const Layer = struct {
    connect: ?[]const u8 = null,
    pubkey: ?[]const u8 = null,
    secret: ?[]const u8 = null,
    expire: ?[]const u8 = null,
    id: ?[]const u8 = null,
    retry: ?bool = null,
    insecure: ?bool = null,
};

pub const Error = error{
    MissingConnect,
    InvalidConnect,
    MissingPubkey,
    InvalidPubkey,
    InvalidExpire,
};

fn first(comptime field: []const u8, layers: []const Layer) @FieldType(Layer, field) {
    for (layers) |l| if (@field(l, field)) |v| return v;
    return null;
}

/// Merges `layers` (highest precedence first) into a Config.
pub fn resolve(layers: []const Layer, now_ms: i64) Error!Config {
    const connect = first("connect", layers) orelse return error.MissingConnect;
    const host, const port = try parseConnect(connect);
    const insecure = first("insecure", layers) orelse false;
    const pubkey: ?[32]u8 = if (first("pubkey", layers)) |k|
        keys.decode(k) catch return error.InvalidPubkey
    else if (insecure) null else return error.MissingPubkey;
    const expire_at_ms: ?i64 = if (first("expire", layers)) |e|
        parseExpire(e, now_ms) catch return error.InvalidExpire
    else
        null;
    return .{
        .host = host,
        .port = port,
        .pubkey = pubkey,
        .insecure = insecure,
        .secret = first("secret", layers) orelse "",
        .retry = first("retry", layers) orelse false,
        .expire_at_ms = expire_at_ms,
        .id = first("id", layers),
    };
}

pub fn parseConnect(text: []const u8) Error!struct { []const u8, u16 } {
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.InvalidConnect;
    const host = std.mem.trim(u8, text[0..colon], "[]");
    if (host.len == 0) return error.InvalidConnect;
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch return error.InvalidConnect;
    return .{ host, port };
}

/// Accepts a duration from now (`90s`, `30m`, `72h`, `7d`) or an absolute UTC
/// time (`2026-10-20T18:00Z`, `2026-10-20T18:00:00Z`, `2026-10-20`).
/// Returns the deadline as Unix milliseconds.
pub fn parseExpire(text: []const u8, now_ms: i64) error{InvalidExpire}!i64 {
    const t = std.mem.trim(u8, text, " ");
    if (t.len < 2) return error.InvalidExpire;
    if (std.mem.indexOfScalar(u8, t, '-') == null) {
        const unit: i64 = switch (t[t.len - 1]) {
            's' => std.time.ms_per_s,
            'm' => std.time.ms_per_min,
            'h' => std.time.ms_per_hour,
            'd' => std.time.ms_per_day,
            else => return error.InvalidExpire,
        };
        const n = std.fmt.parseInt(i64, t[0 .. t.len - 1], 10) catch return error.InvalidExpire;
        if (n <= 0) return error.InvalidExpire;
        return now_ms + n * unit;
    }
    // YYYY-MM-DD[THH:MM[:SS]][Z]
    if (t.len < 10 or t[4] != '-' or t[7] != '-') return error.InvalidExpire;
    const year = std.fmt.parseInt(i32, t[0..4], 10) catch return error.InvalidExpire;
    const month = std.fmt.parseInt(u8, t[5..7], 10) catch return error.InvalidExpire;
    const day = std.fmt.parseInt(u8, t[8..10], 10) catch return error.InvalidExpire;
    var hour: u8 = 0;
    var minute: u8 = 0;
    var second: u8 = 0;
    var rest = t[10..];
    if (rest.len > 0 and (rest[0] == 'T' or rest[0] == ' ')) {
        if (rest.len < 6 or rest[3] != ':') return error.InvalidExpire;
        hour = std.fmt.parseInt(u8, rest[1..3], 10) catch return error.InvalidExpire;
        minute = std.fmt.parseInt(u8, rest[4..6], 10) catch return error.InvalidExpire;
        rest = rest[6..];
        if (rest.len >= 3 and rest[0] == ':') {
            second = std.fmt.parseInt(u8, rest[1..3], 10) catch return error.InvalidExpire;
            rest = rest[3..];
        }
    }
    if (rest.len > 0 and !std.mem.eql(u8, rest, "Z")) return error.InvalidExpire;
    if (month < 1 or month > 12 or day < 1 or day > 31 or hour > 23 or minute > 59 or second > 59)
        return error.InvalidExpire;
    const days = daysFromCivil(year, month, day);
    return ((days * 24 + hour) * 60 + minute) * std.time.ms_per_min + @as(i64, second) * std.time.ms_per_s;
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant).
fn daysFromCivil(y0: i32, m: u8, d: u8) i64 {
    const y: i64 = if (m <= 2) y0 - 1 else y0;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp: i64 = @rem(@as(i64, m) + 9, 12);
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

test "precedence: args > env > baked" {
    const key = "7g0/ietrh5wd/kpAAs130SiVW9Z0++WoaQbcjV3tnCc=";
    const cfg = try resolve(&.{
        .{ .secret = "from-args" },
        .{ .connect = "10.0.0.1:443", .secret = "from-env" },
        .{ .connect = "proxy.example:11601", .pubkey = key, .secret = "baked", .retry = true },
    }, 0);
    try std.testing.expectEqualStrings("10.0.0.1", cfg.host);
    try std.testing.expectEqual(@as(u16, 443), cfg.port);
    try std.testing.expectEqualStrings("from-args", cfg.secret);
    try std.testing.expect(cfg.retry);
    try std.testing.expect(cfg.pubkey != null);
    try std.testing.expectError(error.MissingConnect, resolve(&.{.{}}, 0));
    try std.testing.expectError(error.MissingPubkey, resolve(&.{.{ .connect = "h:1" }}, 0));
    _ = try resolve(&.{.{ .connect = "h:1", .insecure = true }}, 0);
}

test "expire parsing" {
    try std.testing.expectEqual(@as(i64, 1000 + 90 * 60 * 1000), try parseExpire("90m", 1000));
    try std.testing.expectEqual(@as(i64, 72 * 3600 * 1000), try parseExpire("72h", 0));
    // 2026-10-20T18:00Z
    try std.testing.expectEqual(@as(i64, 1792519200000), try parseExpire("2026-10-20T18:00Z", 0));
    try std.testing.expectEqual(@as(i64, 1792519200000), try parseExpire("2026-10-20T18:00:00Z", 0));
    try std.testing.expectEqual(@as(i64, 1792454400000), try parseExpire("2026-10-20", 0));
    try std.testing.expectError(error.InvalidExpire, parseExpire("soon", 0));
    try std.testing.expectError(error.InvalidExpire, parseExpire("2026-13-01", 0));
    try std.testing.expectError(error.InvalidExpire, parseExpire("0h", 0));
}
