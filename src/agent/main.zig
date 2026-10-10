//! zunnel-agent: runs on the remote host, connects back to the proxy and dials
//! TCP/UDP flows on its behalf. Needs no privileges.
//!
//! Settings come from flags, then ZUNNEL_* environment variables, then values
//! baked in at build time (`zig build -Dagent-connect=... -Dagent-pubkey=...`),
//! so a baked agent runs with no arguments.
const std = @import("std");
const builtin = @import("builtin");
const agent = @import("agent.zig");
const config = @import("config.zig");
const baked = @import("agent_options");
const common = @import("common");

// Everything is compiled in; `log_level` filters at runtime (-v).
pub const std_options: std.Options = .{ .log_level = .debug, .logFn = logFn };

var log_level: std.log.Level = .info;

fn logFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (agent.quiet or @intFromEnum(level) > @intFromEnum(log_level)) return;
    var buf: [1024]u8 = undefined;
    std.debug.print("{s}", .{common.logfmt.line(&buf, level, scope, format, args)});
}

const usage =
    \\usage: zunnel-agent -connect <host:port> -pubkey <key> [options]
    \\
    \\  -connect <host:port>  proxy address                       (env ZUNNEL_CONNECT)
    \\  -pubkey <key>         proxy public key (base64)           (env ZUNNEL_PUBKEY)
    \\  -secret <secret>      shared secret printed by the proxy  (env ZUNNEL_SECRET)
    \\  -retry                reconnect forever when the connection drops
    \\  -expire <when>        stop for good at a UTC time (2026-10-20T18:00Z)
    \\                        or after a duration (90m, 72h, 7d)  (env ZUNNEL_EXPIRE)
    \\  -id <id>              override the host-derived agent id  (env ZUNNEL_ID)
    \\  -no-tls               use raw TCP instead of TLS; proxy needs -no-tls too
    \\  -tls-verify           require the proxy's TLS cert to match -connect's host
    \\  -ca <file>            PEM CA bundle used with -tls-verify
    \\  -q                    quiet: print nothing
    \\  -v                    verbose: also log each failed dial and port-unreachable
    \\
    \\Settings may also be baked in at build time, e.g.
    \\  zig build -Drelease -Dagent-connect=proxy:11601 -Dagent-pubkey=<key> -Dagent-secret=<secret>
    \\
;

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print(fmt ++ "\n", args);
    std.process.exit(1);
}

fn argLayer(args: []const [:0]u8) config.Layer {
    var l: config.Layer = .{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = std.mem.trimLeft(u8, args[i], "-");
        const takes_value = for ([_][]const u8{ "connect", "pubkey", "secret", "expire", "id", "ca" }) |n| {
            if (std.mem.eql(u8, a, n)) break true;
        } else false;
        const value: ?[]const u8 = if (takes_value) blk: {
            i += 1;
            if (i >= args.len) fatal("missing value for -{s}", .{a});
            break :blk args[i];
        } else null;
        if (std.mem.eql(u8, a, "connect")) {
            l.connect = value;
        } else if (std.mem.eql(u8, a, "pubkey")) {
            l.pubkey = value;
        } else if (std.mem.eql(u8, a, "secret")) {
            l.secret = value;
        } else if (std.mem.eql(u8, a, "expire")) {
            l.expire = value;
        } else if (std.mem.eql(u8, a, "id")) {
            l.id = value;
        } else if (std.mem.eql(u8, a, "ca")) {
            l.ca = value;
        } else if (std.mem.eql(u8, a, "no-tls")) {
            l.no_tls = true;
        } else if (std.mem.eql(u8, a, "tls-verify")) {
            l.tls_verify = true;
        } else if (std.mem.eql(u8, a, "retry")) {
            l.retry = true;
        } else if (std.mem.eql(u8, a, "q")) {
            agent.quiet = true;
        } else if (std.mem.eql(u8, a, "v")) {
            log_level = .debug;
        } else if (std.mem.eql(u8, a, "h") or std.mem.eql(u8, a, "help")) {
            std.debug.print("{s}", .{usage});
            std.process.exit(0);
        } else {
            fatal("unknown option '{s}'\n\n{s}", .{ args[i], usage });
        }
    }
    return l;
}

fn envLayer(gpa: std.mem.Allocator) config.Layer {
    const get = struct {
        fn f(a: std.mem.Allocator, name: []const u8) ?[]const u8 {
            return std.process.getEnvVarOwned(a, name) catch null;
        }
    }.f;
    return .{
        .connect = get(gpa, "ZUNNEL_CONNECT"),
        .pubkey = get(gpa, "ZUNNEL_PUBKEY"),
        .secret = get(gpa, "ZUNNEL_SECRET"),
        .expire = get(gpa, "ZUNNEL_EXPIRE"),
        .id = get(gpa, "ZUNNEL_ID"),
        .ca = get(gpa, "ZUNNEL_CA"),
    };
}

fn bakedLayer() config.Layer {
    return .{
        .connect = baked.connect,
        .pubkey = baked.pubkey,
        .secret = baked.secret,
        .expire = baked.expire,
        .id = baked.id,
        .ca = baked.ca,
        .no_tls = baked.no_tls,
        .tls_verify = baked.tls_verify,
        // A baked agent is meant to stay up: reconnect unless told otherwise.
        .retry = baked.retry orelse if (baked.connect != null) true else null,
    };
}

pub fn main() !void {
    // -Dagent-windowed builds use the Windows GUI subsystem: there is no
    // console to print to on launch, so silence the log channel. Operators
    // who need output can still start it from a terminal and use `-v`.
    if (baked.windowed and builtin.os.tag == .windows) agent.quiet = true;

    const gpa = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(gpa);
    const layers = [_]config.Layer{ argLayer(args), envLayer(gpa), bakedLayer() };
    const cfg = config.resolve(&layers, std.time.milliTimestamp()) catch |err| switch (err) {
        error.MissingConnect => fatal("{s}", .{usage}),
        error.InvalidConnect => fatal("-connect expects host:port", .{}),
        error.MissingPubkey => fatal("-pubkey is required", .{}),
        error.InvalidPubkey => fatal("invalid -pubkey", .{}),
        error.InvalidExpire => fatal("invalid -expire (use e.g. 2026-10-20T18:00Z, 90m, 72h or 7d)", .{}),
    };

    var stop = std.atomic.Value(bool).init(false);
    switch (agent.run(gpa, cfg, &stop)) {
        .stopped, .disconnected => {},
        .killed => std.process.exit(0),
        .expired => {
            if (!agent.quiet) std.debug.print("agent expired\n", .{});
            std.process.exit(0);
        },
    }
}

test {
    _ = agent;
    _ = config;
    _ = @import("identity.zig");
    _ = @import("netinfo.zig");
}
