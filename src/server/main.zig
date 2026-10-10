//! zunnel-server: runs on the operator machine. Accepts agents, exposes TUN
//! interfaces routed through them, and manages listeners on the agents.
const std = @import("std");
const builtin = @import("builtin");
const common = @import("common");
const privileges = @import("privileges.zig");
const ui = @import("ui.zig");
const lineedit = @import("lineedit.zig");
const tun = @import("tun.zig");
const tls = @import("tls.zig");
const server_mod = @import("server.zig");
const tunnel_mod = @import("tunnel.zig");
const Tunnel = tunnel_mod.Tunnel;

const Server = server_mod.Server;
const Session = server_mod.Session;
const keys = common.keys;
const Allocator = std.mem.Allocator;

// Everything is compiled in; ui.level filters at runtime (-v / -q).
pub const std_options: std.Options = .{ .log_level = .debug, .logFn = ui.logFn };

const usage =
    \\usage: zunnel-server [options]
    \\
    \\  -listen <addr:port>  address agents connect to (default 0.0.0.0:11601)
    \\  -key <file>          server key and shared secret, created if missing (default zunnel.key)
    \\  -secret <secret>     override the shared secret stored in the key file
    \\  -no-secret           accept agents without a secret (not recommended)
    \\  -no-tls              accept raw TCP only (no TLS; agents need -no-tls too)
    \\  -cert <file>         TLS certificate (default zunnel.cert, generated if missing)
    \\  -cert-key <file>     TLS private key (default zunnel.cert.key, generated if missing)
    \\  -config <file>       run the console commands in <file> at startup (see `save`)
    \\  -log <file>          append timestamped events and log lines to <file>
    \\  -v / -q              verbose (debug) / quiet (warnings and events only)
    \\  -tun <name>          default TUN interface name (default zunnel)
    \\  -route <cidr>        route a network through the default interface (repeatable)
    \\  -autostart           create the default interface at startup and attach the first agent
    \\  -localhost-net <cidr> destinations in this network reach the agent's 127.0.0.1
    \\                       (default 240.0.0.0/4; Windows cannot route 240/4, use e.g. 198.18.255.0/24)
    \\  -dial-timeout <ms>   how long agents try to connect before giving up (default 3000)
    \\  -max-dials <n>       max connects in flight per interface; extra SYNs queue (default 256)
    \\
;

const Options = struct {
    listen: std.net.Address = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, common.proto.default_port),
    key_file: []const u8 = "zunnel.key",
    secret: ?[]const u8 = null,
    no_secret: bool = false,
    no_tls: bool = false,
    cert_file: []const u8 = "zunnel.cert",
    cert_key_file: []const u8 = "zunnel.cert.key",
    config_file: ?[]const u8 = null,
    log_file: ?[]const u8 = null,
    tun_name: []const u8 = "zunnel",
    localhost_net: tun.Cidr = tun.Cidr.parse("240.0.0.0/4") catch unreachable,
    routes: std.ArrayList([]const u8) = .empty,
    autostart: bool = false,
    dial_timeout_ms: u16 = common.proto.default_dial_timeout_ms,
    max_dials: u32 = 256,
};

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print(fmt ++ "\n", args);
    std.process.exit(1);
}

fn parseArgs(gpa: Allocator, args: []const [:0]u8) !Options {
    var o: Options = .{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = std.mem.trimLeft(u8, args[i], "-");
        if (std.mem.eql(u8, a, "autostart")) {
            o.autostart = true;
            continue;
        }
        if (std.mem.eql(u8, a, "no-secret")) {
            o.no_secret = true;
            continue;
        }
        if (std.mem.eql(u8, a, "no-tls")) {
            o.no_tls = true;
            continue;
        }
        if (std.mem.eql(u8, a, "v")) {
            ui.level = .debug;
            continue;
        }
        if (std.mem.eql(u8, a, "q")) {
            ui.level = .warn;
            continue;
        }
        if (std.mem.eql(u8, a, "h") or std.mem.eql(u8, a, "help")) {
            std.debug.print("{s}", .{usage});
            std.process.exit(0);
        }
        i += 1;
        if (i >= args.len) fatal("unknown option or missing value: {s}\n\n{s}", .{ args[i - 1], usage });
        const v = args[i];
        if (std.mem.eql(u8, a, "listen")) {
            o.listen = std.net.Address.parseIpAndPort(v) catch fatal("invalid -listen address '{s}'", .{v});
        } else if (std.mem.eql(u8, a, "key")) {
            o.key_file = v;
        } else if (std.mem.eql(u8, a, "secret")) {
            o.secret = v;
        } else if (std.mem.eql(u8, a, "cert")) {
            o.cert_file = v;
        } else if (std.mem.eql(u8, a, "cert-key")) {
            o.cert_key_file = v;
        } else if (std.mem.eql(u8, a, "config")) {
            o.config_file = v;
        } else if (std.mem.eql(u8, a, "log")) {
            o.log_file = v;
        } else if (std.mem.eql(u8, a, "localhost-net")) {
            o.localhost_net = tun.Cidr.parse(v) catch fatal("invalid -localhost-net '{s}'", .{v});
        } else if (std.mem.eql(u8, a, "dial-timeout")) {
            o.dial_timeout_ms = std.fmt.parseInt(u16, v, 10) catch fatal("invalid -dial-timeout '{s}' (milliseconds, max 65535)", .{v});
            if (o.dial_timeout_ms == 0) fatal("-dial-timeout must be > 0", .{});
        } else if (std.mem.eql(u8, a, "max-dials")) {
            o.max_dials = std.fmt.parseInt(u32, v, 10) catch fatal("invalid -max-dials '{s}'", .{v});
            if (o.max_dials == 0) fatal("-max-dials must be > 0", .{});
        } else if (std.mem.eql(u8, a, "tun")) {
            o.tun_name = v;
        } else if (std.mem.eql(u8, a, "route")) {
            if (!tun.validateCidr(v)) fatal("invalid -route '{s}' (expected e.g. 10.0.0.0/24)", .{v});
            try o.routes.append(gpa, v);
        } else {
            fatal("unknown option '{s}'\n\n{s}", .{ args[i - 1], usage });
        }
    }
    return o;
}

pub fn main() !void {
    const gpa = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(gpa);
    const opts = try parseArgs(gpa, args);
    if (privileges.check(opts.tun_name)) |problem| fatal("{s}", .{problem});
    if (opts.log_file) |path| ui.openLog(path) catch |err| fatal("cannot open log file '{s}': {s}", .{ path, @errorName(err) });

    const ident = keys.loadOrCreate(opts.key_file) catch |err|
        fatal("cannot load key file '{s}': {s}", .{ opts.key_file, @errorName(err) });
    if (ident.created) std.debug.print("generated a new key and secret in {s}\n", .{opts.key_file});
    if (ident.added_secret) std.debug.print("added a shared secret to {s}\n", .{opts.key_file});
    const pubkey = keys.encode(ident.keypair.public_key);
    if (opts.no_secret and opts.secret != null) fatal("-secret and -no-secret are mutually exclusive", .{});
    const secret: []const u8 = if (opts.no_secret) "" else opts.secret orelse &ident.secret;

    const tls_server = if (opts.no_tls) null else tls.Server.init(gpa, opts.cert_file, opts.cert_key_file) catch |err|
        fatal("cannot initialise TLS ({s}, {s}): {s}", .{ opts.cert_file, opts.cert_key_file, @errorName(err) });

    var server: Server = .{
        .gpa = gpa,
        .static = ident.keypair,
        .psk = common.noise.pskFromSecret(secret),
        .no_secret = opts.no_secret,
        .autostart = opts.autostart,
        .listen_address = opts.listen,
        .default_iface = opts.tun_name,
        .default_localhost_net = opts.localhost_net,
        .dial_timeout_ms = opts.dial_timeout_ms,
        .max_dials = opts.max_dials,
        .tls_server = tls_server,
    };
    var console: Console = .{ .gpa = gpa, .server = &server, .pending_routes = opts.routes, .config_path = opts.config_file };
    installShutdownHandlers(&server);
    if (opts.autostart) _ = console.ensureTunnel(opts.tun_name) orelse std.process.exit(1);

    server.listen() catch |err| fatal("cannot listen on {f}: {s}", .{ opts.listen, @errorName(err) });

    const port = opts.listen.getPort();
    const transport_desc = if (tls_server == null) " (TLS off; agents need -no-tls)" else "";
    std.debug.print("zunnel server {s} listening on {f}{s}\npublic key: {s}\n", .{ common.version, opts.listen, transport_desc, &pubkey });
    const agent_tls_flag: []const u8 = if (tls_server == null) " -no-tls" else "";
    if (secret.len > 0) {
        std.debug.print(
            \\agent:      zunnel-agent -connect <this-host>:{d} -pubkey {s} -secret {s}{s}
            \\baked:      zig build -Drelease -Dtarget=<target> -Dagent-connect=<this-host>:{d} -Dagent-pubkey={s} -Dagent-secret={s}
            \\
        , .{ port, &pubkey, secret, agent_tls_flag, port, &pubkey, secret });
    } else {
        std.debug.print(
            \\agent:      zunnel-agent -connect <this-host>:{d} -pubkey {s}{s}
            \\WARNING: -no-secret: anyone who has the public key can connect as an agent
            \\
        , .{ port, &pubkey, agent_tls_flag });
    }
    if (tls_server == null) std.debug.print("WARNING: -no-tls: zunnel is now distinguishable on the wire\n", .{});
    std.debug.print("type 'help' for commands\n", .{});
    if (opts.config_file) |path| console.runConfig(path);
    console.run();
}

// ------------------------------------------------------- graceful shutdown

var shutdown_server: ?*Server = null;
var stop_requested = std.atomic.Value(bool).init(false);

/// Ctrl-C / SIGTERM / closing the console window remove routes, adapters and
/// firewall rules before exiting.
fn installShutdownHandlers(server: *Server) void {
    shutdown_server = server;
    if (builtin.os.tag == .windows) {
        // Runs on its own thread, so it may do the full shutdown itself.
        _ = std.os.windows.kernel32.SetConsoleCtrlHandler(onConsoleCtrl, std.os.windows.TRUE);
    } else {
        // Signal handlers may only set a flag; a watcher thread does the work.
        const act: std.posix.Sigaction = .{
            .handler = .{ .handler = onSignal },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.INT, &act, null);
        std.posix.sigaction(std.posix.SIG.TERM, &act, null);
        const t = std.Thread.spawn(.{}, shutdownWatcher, .{}) catch return;
        t.detach();
    }
}

fn onConsoleCtrl(_: std.os.windows.DWORD) callconv(.winapi) std.os.windows.BOOL {
    quit();
}

/// Restores the terminal, removes interfaces and routes, and exits.
fn quit() noreturn {
    ui.restoreTerminal();
    std.debug.print("shutting down...\n", .{});
    if (shutdown_server) |s| s.shutdown();
    std.process.exit(0);
}

fn onSignal(_: c_int) callconv(.c) void {
    stop_requested.store(true, .release);
}

fn shutdownWatcher() void {
    while (!stop_requested.load(.acquire)) std.Thread.sleep(100 * std.time.ns_per_ms);
    quit();
}

const help_text =
    \\  sessions                                   list connected agents
    \\  start [agent] [iface]                      route an interface through an agent
    \\                                             (creates it if needed, and binds it so it
    \\                                             re-attaches whenever that agent reconnects)
    \\  stop [iface]                               detach and unbind an interface
    \\  bind <iface> <agent|ident>                 attach <iface> to that agent whenever it
    \\                                             connects (works while it is offline)
    \\  unbind <iface>                             remove a binding
    \\  bindings                                   list bindings
    \\  ifaces                                     list tunnel interfaces and routes
    \\  iface add <name> [localhost-net]           create a tunnel interface
    \\  iface del <name>                           delete a tunnel interface
    \\  route add <cidr> [iface]                   route a network through an interface
    \\  route del <cidr> [iface]                   remove a route
    \\  listener add <agent> <tcp|udp> <bind> <target>
    \\                                             listen on the agent; connections are
    \\                                             forwarded to <target>, dialed by the server
    \\  listener del <id>                          remove a listener
    \\  listeners                                  list listeners
    \\  relay <agent> [bind]                       let deeper agents connect through
    \\                                             <agent> (default bind 0.0.0.0:11601)
    \\  flows [iface] [n]                          active connections with byte counts (n=50)
    \\  ifconfig [agent]                           the agent's interfaces, with suggested routes
    \\  session info [agent]                       details about an agent
    \\  kill <agent>                               shut an agent down for good (no reconnect)
    \\  save [file]                                write interfaces, routes, bindings and
    \\                                             listeners as commands (for -config)
    \\  exit                                       quit
    \\
    \\  [iface] defaults to the -tun name; [agent] defaults to the only agent.
    \\  <agent> is a session number or a unique prefix of the agent's IDENT.
    \\  Listeners and bindings follow the agent's IDENT, so they come back when it
    \\  reconnects; for an offline agent, give its full IDENT.
    \\
;

const Console = struct {
    gpa: Allocator,
    server: *Server,
    /// -route values for the default interface, applied when it is created.
    pending_routes: std.ArrayList([]const u8) = .empty,
    /// -config file; the default target of `save`.
    config_path: ?[]const u8 = null,

    const prompt = "zunnel> ";

    fn run(self: *Console) void {
        if (lineedit.Terminal.interactive() and ui.terminal.enterRaw()) return self.runInteractive();
        // Not a terminal (piped/redirected stdin, services): plain line reading.
        var buf: [1024]u8 = undefined;
        var reader = std.fs.File.stdin().reader(&buf);
        while (true) {
            std.debug.print(prompt, .{});
            const line = reader.interface.takeDelimiter('\n') catch break orelse break;
            self.exec(std.mem.trim(u8, line, " \t\r"));
        }
        // stdin closed (e.g. running as a service): keep serving.
        while (true) std.Thread.sleep(std.time.ns_per_hour);
    }

    /// Terminal console: line editing, history (~/.zunnel_history) and tab
    /// completion; output from other threads redraws around the input line.
    fn runInteractive(self: *Console) void {
        var ed: lineedit.Editor = .{ .gpa = self.gpa };
        const history_path = historyPath(self.gpa);
        if (history_path) |p| loadHistory(&ed, p);
        ui.showLine(prompt, "", 0);
        while (lineedit.Terminal.readByte()) |b| {
            switch (ed.feed(b)) {
                .none => {},
                .redraw => ui.showLine(prompt, ed.line(), ed.cursor),
                .submit => {
                    var copy: [lineedit.max_line]u8 = undefined;
                    const line = copy[0..ed.len];
                    @memcpy(line, ed.line());
                    ui.endLine();
                    ed.remember(line);
                    if (history_path) |p| appendHistory(p, line);
                    ed.reset();
                    self.exec(std.mem.trim(u8, line, " \t"));
                    ui.showLine(prompt, "", 0);
                },
                .eof => {
                    ui.endLine();
                    quit();
                },
                .complete => {
                    var store: Completions = .{};
                    self.complete(ed.beforeCursor(), &store);
                    if (ed.applyCompletion(store.items[0..store.n])) {
                        var list: [2048]u8 = undefined;
                        var w = std.Io.Writer.fixed(&list);
                        for (store.items[0..store.n]) |c| w.print("{s}  ", .{c}) catch break;
                        w.writeAll("\n") catch {};
                        ui.out(w.buffered());
                    }
                    ui.showLine(prompt, ed.line(), ed.cursor);
                },
                .clear_screen => {
                    std.fs.File.stderr().writeAll("\x1b[2J\x1b[H") catch {};
                    ui.showLine(prompt, ed.line(), ed.cursor);
                },
            }
        }
        // Input closed: keep serving without a console.
        ui.restoreTerminal();
        while (true) std.Thread.sleep(std.time.ns_per_hour);
    }

    fn historyPath(gpa: Allocator) ?[]const u8 {
        const home = std.process.getEnvVarOwned(gpa, if (builtin.os.tag == .windows) "USERPROFILE" else "HOME") catch return null;
        return std.fs.path.join(gpa, &.{ home, ".zunnel_history" }) catch null;
    }

    fn loadHistory(ed: *lineedit.Editor, path: []const u8) void {
        const data = std.fs.cwd().readFileAlloc(ed.gpa, path, 1024 * 1024) catch return;
        defer ed.gpa.free(data);
        var lines = std.mem.tokenizeAny(u8, data, "\r\n");
        while (lines.next()) |l| ed.remember(l);
    }

    fn appendHistory(path: []const u8, line: []const u8) void {
        const t = std.mem.trim(u8, line, " \t");
        if (t.len == 0) return;
        const f = std.fs.cwd().createFile(path, .{ .truncate = false }) catch return;
        defer f.close();
        f.seekFromEnd(0) catch return;
        f.writeAll(t) catch return;
        f.writeAll("\n") catch {};
    }

    // ---------------------------------------------------------- completion

    const Completions = struct {
        items: [64][]const u8 = undefined,
        n: usize = 0,
        text: [2048]u8 = undefined,
        used: usize = 0,

        fn add(self: *Completions, prefix: []const u8, candidate: []const u8) void {
            if (!std.mem.startsWith(u8, candidate, prefix)) return;
            if (self.n == self.items.len or self.used + candidate.len > self.text.len) return;
            for (self.items[0..self.n]) |c| if (eql(c, candidate)) return;
            const dst = self.text[self.used..][0..candidate.len];
            @memcpy(dst, candidate);
            self.used += candidate.len;
            self.items[self.n] = dst;
            self.n += 1;
        }
    };

    const commands = [_][]const u8{
        "sessions", "start",     "stop",     "bind",  "unbind",   "bindings", "ifaces",
        "iface",    "route",     "listener", "listeners", "relay", "flows", "ifconfig",
        "session",  "kill",      "save",     "help",  "exit",
    };

    /// Fills `out` with candidates for the word being typed at the end of `before`.
    fn complete(self: *Console, before: []const u8, out: *Completions) void {
        var words: [8][]const u8 = undefined;
        var n: usize = 0;
        var it = std.mem.tokenizeScalar(u8, before, ' ');
        while (it.next()) |w| : (n += 1) if (n < words.len) {
            words[n] = w;
        };
        n = @min(n, words.len);
        const new_word = before.len == 0 or before[before.len - 1] == ' ';
        const idx = if (new_word) n else n - 1;
        const prefix = if (new_word) "" else words[n - 1];
        if (idx == 0) {
            for (commands) |c| out.add(prefix, c);
            return;
        }
        const cmd = words[0];
        const sub = if (idx >= 2) words[1] else "";
        const Kind = enum { none, agents, ifaces, listeners };
        var kind: Kind = .none;
        if (eql(cmd, "start")) {
            kind = if (idx == 1) .agents else if (idx == 2) .ifaces else .none;
        } else if (eql(cmd, "stop") or eql(cmd, "flows") or eql(cmd, "unbind")) {
            kind = if (idx == 1) .ifaces else .none;
        } else if (eql(cmd, "kill") or eql(cmd, "ifconfig") or eql(cmd, "relay")) {
            kind = if (idx == 1) .agents else .none;
        } else if (eql(cmd, "bind")) {
            kind = if (idx == 1) .ifaces else if (idx == 2) .agents else .none;
        } else if (eql(cmd, "session")) {
            if (idx == 1) out.add(prefix, "info");
            if (idx == 2) kind = .agents;
        } else if (eql(cmd, "iface")) {
            if (idx == 1) for ([_][]const u8{ "add", "del" }) |c| out.add(prefix, c);
            if (idx == 2 and eql(sub, "del")) kind = .ifaces;
        } else if (eql(cmd, "route")) {
            if (idx == 1) for ([_][]const u8{ "add", "del", "list" }) |c| out.add(prefix, c);
            if (idx == 3) kind = .ifaces;
            if (idx >= 3 and eql(sub, "add")) out.add(prefix, "force");
        } else if (eql(cmd, "listener")) {
            if (idx == 1) for ([_][]const u8{ "add", "del", "list" }) |c| out.add(prefix, c);
            if (idx == 2) kind = if (eql(sub, "add")) .agents else if (eql(sub, "del")) .listeners else .none;
            if (idx == 3 and eql(sub, "add")) for ([_][]const u8{ "tcp", "udp" }) |c| out.add(prefix, c);
        }
        if (kind == .none) return;

        self.server.mutex.lock();
        defer self.server.mutex.unlock();
        switch (kind) {
            .agents => for (self.server.sessions.items) |s| {
                var num: [12]u8 = undefined;
                out.add(prefix, std.fmt.bufPrint(&num, "{d}", .{s.id}) catch continue);
                out.add(prefix, s.ident);
            },
            .ifaces => for (self.server.tunnels.items) |t| out.add(prefix, t.name),
            .listeners => for (self.server.listeners.items) |l| {
                var num: [12]u8 = undefined;
                out.add(prefix, std.fmt.bufPrint(&num, "{d}", .{l.id}) catch continue);
            },
            .none => {},
        }
    }

    fn exec(self: *Console, line: []const u8) void {
        var argv: [8][]const u8 = undefined;
        var n: usize = 0;
        var it = std.mem.tokenizeAny(u8, line, " \t");
        while (it.next()) |tok| {
            if (n == argv.len) break;
            argv[n] = tok;
            n += 1;
        }
        if (n == 0) return;
        const cmd = argv[0];
        const args = argv[1..n];

        if (eql(cmd, "help") or eql(cmd, "?")) {
            std.debug.print("{s}", .{help_text});
        } else if (eql(cmd, "sessions") or eql(cmd, "ls")) {
            self.listSessions();
        } else if (eql(cmd, "start")) {
            self.start(at(args, 0), at(args, 1));
        } else if (eql(cmd, "stop")) {
            self.stop(at(args, 0) orelse self.server.default_iface);
        } else if (eql(cmd, "ifaces") or eql(cmd, "status")) {
            self.listIfaces();
        } else if (eql(cmd, "iface")) {
            self.iface(args);
        } else if (eql(cmd, "route") or eql(cmd, "routes")) {
            self.route(args);
        } else if (eql(cmd, "listeners")) {
            self.listListeners();
        } else if (eql(cmd, "listener")) {
            self.listener(args);
        } else if (eql(cmd, "relay")) {
            self.relay(at(args, 0), at(args, 1));
        } else if (eql(cmd, "kill")) {
            self.kill(at(args, 0));
        } else if (eql(cmd, "flows")) {
            self.flows(args);
        } else if (eql(cmd, "ifconfig")) {
            self.ifconfig(at(args, 0));
        } else if (eql(cmd, "session")) {
            if (args.len < 1 or !eql(args[0], "info")) return std.debug.print("usage: session info [agent]\n", .{});
            self.sessionInfo(at(args, 1));
        } else if (eql(cmd, "bind")) {
            self.bindCmd(args);
        } else if (eql(cmd, "unbind")) {
            self.unbind(at(args, 0));
        } else if (eql(cmd, "bindings")) {
            self.bindCmd(&.{});
        } else if (eql(cmd, "save")) {
            self.save(at(args, 0) orelse self.config_path orelse "zunnel.conf");
        } else if (eql(cmd, "exit") or eql(cmd, "quit")) {
            quit();
        } else {
            std.debug.print("unknown command '{s}', try 'help'\n", .{cmd});
        }
    }

    // ------------------------------------------------------------ agents

    fn listSessions(self: *Console) void {
        const server = self.server;
        server.mutex.lock();
        defer server.mutex.unlock();
        if (server.sessions.items.len == 0) return std.debug.print("no agents connected\n", .{});
        std.debug.print("  {s:<4} {s:<16} {s:<28} {s:<16} {s:<22} {s}\n", .{ "ID", "IDENT", "AGENT", "OS", "REMOTE", "TUNNELS" });
        for (server.sessions.items) |s| {
            var name_buf: [64]u8 = undefined;
            var os_buf: [32]u8 = undefined;
            var remote_buf: [64]u8 = undefined;
            var ifaces_buf: [128]u8 = undefined;
            const agent_name = std.fmt.bufPrint(&name_buf, "{s}@{s}", .{ s.user, s.hostname }) catch s.hostname;
            const os = std.fmt.bufPrint(&os_buf, "{s}/{s}", .{ s.os, s.arch }) catch s.os;
            const remote = if (s.via) |v|
                std.fmt.bufPrint(&remote_buf, "via agent #{d}", .{v}) catch "?"
            else
                std.fmt.bufPrint(&remote_buf, "{f}", .{s.remote}) catch "?";
            var w = std.Io.Writer.fixed(&ifaces_buf);
            for (server.tunnels.items) |t| if (t.activeSession() == s) w.print("{s} ", .{t.name}) catch {};
            std.debug.print("  {d:<4} {s:<16} {s:<28} {s:<16} {s:<22} {s}\n", .{ s.id, s.ident, agent_name, os, remote, w.buffered() });
            if (s.expire_ms) |deadline| {
                const left: u64 = @intCast(@max(0, @divTrunc(deadline - std.time.milliTimestamp(), 1000)));
                std.debug.print("       expires in {d}h{d:0>2}m{d:0>2}s\n", .{ left / 3600, left % 3600 / 60, left % 60 });
            }
        }
    }

    /// Resolves an agent argument: a session number (`3`, `#3`), a unique
    /// prefix of an agent identity, or nothing (the only agent). Caller holds
    /// server.mutex.
    fn resolveAgentLocked(self: *Console, id_arg: ?[]const u8) ?*Session {
        const sessions = self.server.sessions.items;
        if (id_arg) |a| {
            if (std.fmt.parseInt(u32, std.mem.trimLeft(u8, a, "#"), 10)) |id| {
                if (self.server.findSessionLocked(id)) |s| return s;
            } else |_| {}
            var found: ?*Session = null;
            for (sessions) |s| {
                if (!std.mem.startsWith(u8, s.ident, a)) continue;
                if (found != null) {
                    std.debug.print("'{s}' matches more than one agent; use more of the identity\n", .{a});
                    return null;
                }
                found = s;
            }
            return found orelse {
                std.debug.print("no agent '{s}'\n", .{a});
                return null;
            };
        }
        if (sessions.len != 1) {
            std.debug.print("{d} agents connected, specify an agent id\n", .{sessions.len});
            return null;
        }
        return sessions[0];
    }

    /// `flows [iface] [n]`: active connections with their byte counts.
    fn flows(self: *Console, args: []const []const u8) void {
        var name: ?[]const u8 = null;
        var limit: usize = 50;
        for (args) |a| {
            if (std.fmt.parseInt(usize, a, 10)) |n| limit = n else |_| name = a;
        }
        self.server.mutex.lock();
        defer self.server.mutex.unlock();
        var any = false;
        for (self.server.tunnels.items) |t| {
            if (name) |n| if (!eql(n, t.name)) continue;
            any = true;
            std.debug.print("{s}:\n", .{t.name});
            t.printFlows(limit);
        }
        if (!any) std.debug.print("{s}\n", .{if (name != null) "no such interface" else "no tunnel interfaces"});
    }

    /// Asks an agent for its interfaces; the answer is printed when it arrives.
    fn ifconfig(self: *Console, agent_arg: ?[]const u8) void {
        self.server.mutex.lock();
        defer self.server.mutex.unlock();
        const s = self.resolveAgentLocked(agent_arg) orelse return;
        s.link.send(.info_request, 1, &.{}) catch return std.debug.print("agent #{d} is disconnecting\n", .{s.id});
    }

    fn sessionInfo(self: *Console, agent_arg: ?[]const u8) void {
        const server = self.server;
        server.mutex.lock();
        defer server.mutex.unlock();
        const s = self.resolveAgentLocked(agent_arg) orelse return;
        const up: u64 = @intCast(@max(0, @divTrunc(common.clock.monotonicMs() - s.joined_ms, 1000)));
        std.debug.print("agent #{d}\n  ident     {s}\n  user      {s}\n  host      {s}\n  os/arch   {s}/{s}\n  pid       {s}\n  version   {s}\n", .{
            s.id, s.ident, s.user, s.hostname, s.os, s.arch, s.pid, s.version,
        });
        if (s.via) |v| {
            std.debug.print("  remote    via agent #{d}\n", .{v});
        } else std.debug.print("  remote    {f}\n", .{s.remote});
        std.debug.print("  connected {d}h{d:0>2}m{d:0>2}s ago\n", .{ up / 3600, up % 3600 / 60, up % 60 });
        if (s.expire_ms) |deadline| {
            // -expire is a wall-clock deadline (Unix ms).
            const left: u64 = @intCast(@max(0, @divTrunc(deadline - std.time.milliTimestamp(), 1000)));
            std.debug.print("  expires   in {d}h{d:0>2}m{d:0>2}s\n", .{ left / 3600, left % 3600 / 60, left % 60 });
        }
        std.debug.print("  link      {d} bytes sent, {d} received\n", .{ s.link.bytes_tx.load(.monotonic), s.link.bytes_rx.load(.monotonic) });
        for (server.tunnels.items) |t| if (t.activeSession() == s) std.debug.print("  tunnel    {s}\n", .{t.name});
        for (server.bindings.items) |b| if (std.mem.eql(u8, b.ident, s.ident)) std.debug.print("  bound     {s}\n", .{b.iface});
        for (server.listeners.items) |l| if (l.session == s) std.debug.print("  listener  #{d} {s} {f} -> {f}{s}\n", .{
            l.id, @tagName(l.transport), l.bind, l.target, if (l.active) "" else " (pending)",
        });
    }

    /// Tells an agent to shut down for good; it will not reconnect.
    fn kill(self: *Console, agent_arg: ?[]const u8) void {
        const arg = agent_arg orelse return std.debug.print("usage: kill <agent>\n", .{});
        self.server.mutex.lock();
        defer self.server.mutex.unlock();
        const s = self.resolveAgentLocked(arg) orelse return;
        s.link.send(.kill, 0, &.{}) catch return std.debug.print("agent #{d} is already disconnecting\n", .{s.id});
        ui.event("sent kill to agent #{d} ({s}@{s}); it will not reconnect", .{ s.id, s.user, s.hostname });
    }

    // ------------------------------------------------------------ tunnels

    fn ensureTunnel(self: *Console, name: []const u8) ?*Tunnel {
        if (self.server.findTunnel(name)) |t| return t;
        return self.createTunnel(name, self.server.default_localhost_net);
    }

    fn createTunnel(self: *Console, name: []const u8, localhost_net: tun.Cidr) ?*Tunnel {
        const t = self.server.createTunnel(name, localhost_net) catch |err| {
            std.debug.print("cannot create tunnel interface '{s}': {s}\n", .{ name, @errorName(err) });
            return null;
        };
        ui.event("created tunnel interface {s}", .{name});
        if (std.mem.eql(u8, name, self.server.default_iface)) {
            for (self.pending_routes.items) |r| addRoute(t, r);
            self.pending_routes.clearRetainingCapacity();
        }
        return t;
    }

    fn start(self: *Console, agent_arg: ?[]const u8, iface_arg: ?[]const u8) void {
        const name = iface_arg orelse self.server.default_iface;
        // Resolve the agent first so a typo does not create an interface.
        {
            self.server.mutex.lock();
            defer self.server.mutex.unlock();
            _ = self.resolveAgentLocked(agent_arg) orelse return;
        }
        const t = self.ensureTunnel(name) orelse return;
        self.server.mutex.lock();
        defer self.server.mutex.unlock();
        const s = self.resolveAgentLocked(agent_arg) orelse return;
        if (t.activeSession()) |prev| if (prev != s) std.debug.print("note: {s} was routed through agent #{d}\n", .{ name, prev.id });
        t.attach(s);
        self.server.setBindingLocked(name, s.ident) catch {};
        ui.event("tunnel {s} now routes through agent #{d} ({s}@{s}); re-attaches when it reconnects", .{ name, s.id, s.user, s.hostname });
    }

    fn stop(self: *Console, name: []const u8) void {
        self.server.mutex.lock();
        defer self.server.mutex.unlock();
        const t = self.server.findTunnelLocked(name) orelse return std.debug.print("no interface '{s}'\n", .{name});
        const unbound = self.server.removeBindingLocked(name);
        if (t.activeSession()) |s| {
            _ = t.detach(s);
            ui.event("{s} stopped", .{name});
        } else if (unbound) {
            ui.event("{s} unbound", .{name});
        } else std.debug.print("{s} has no agent\n", .{name});
    }

    /// Finds a connected agent by session number or unique IDENT prefix,
    /// without printing anything. Caller holds server.mutex.
    fn findAgentLocked(self: *Console, arg: []const u8) ?*Session {
        if (std.fmt.parseInt(u32, std.mem.trimLeft(u8, arg, "#"), 10)) |id| {
            if (self.server.findSessionLocked(id)) |s| return s;
        } else |_| {}
        var found: ?*Session = null;
        for (self.server.sessions.items) |s| {
            if (!std.mem.startsWith(u8, s.ident, arg)) continue;
            if (found != null) return null;
            found = s;
        }
        return found;
    }

    /// Resolves an <agent|ident> argument to an identity, copied into `buf`:
    /// a connected agent's IDENT, or the argument itself taken as the full
    /// IDENT of an agent that is offline. Caller holds server.mutex.
    fn resolveIdentLocked(self: *Console, arg: ?[]const u8, buf: []u8) ?[]const u8 {
        const s = if (arg) |a| self.findAgentLocked(a) else self.resolveAgentLocked(null);
        const ident = if (s) |x| x.ident else blk: {
            const a = arg orelse return null;
            if (std.fmt.parseInt(u32, std.mem.trimLeft(u8, a, "#"), 10)) |_| {
                std.debug.print("no agent #{s}\n", .{std.mem.trimLeft(u8, a, "#")});
                return null;
            } else |_| {}
            std.debug.print("no connected agent matches '{s}'; treating it as the IDENT of an offline agent\n", .{a});
            break :blk a;
        };
        if (ident.len > buf.len) return null;
        @memcpy(buf[0..ident.len], ident);
        return buf[0..ident.len];
    }

    fn bindCmd(self: *Console, args: []const []const u8) void {
        self.server.mutex.lock();
        defer self.server.mutex.unlock();
        if (args.len == 0) {
            if (self.server.bindings.items.len == 0) return std.debug.print("no bindings\n", .{});
            for (self.server.bindings.items) |b| {
                const t = self.server.findTunnelLocked(b.iface);
                const state = if (t == null) "(no such interface)" else if (t.?.activeSession() != null) "(attached)" else "(waiting for agent)";
                std.debug.print("  {s:<12} -> {s}  {s}\n", .{ b.iface, b.ident, state });
            }
            return;
        }
        if (args.len < 2) return std.debug.print("usage: bind <iface> <agent|ident>\n", .{});
        var buf: [64]u8 = undefined;
        const ident = self.resolveIdentLocked(args[1], &buf) orelse return;
        self.server.setBindingLocked(args[0], ident) catch |err| return std.debug.print("bind failed: {s}\n", .{@errorName(err)});
        if (self.server.attachBoundLocked(args[0], ident)) |s| {
            ui.event("{s} bound to {s}; now routes through agent #{d}", .{ args[0], ident, s.id });
        } else if (self.server.findTunnelLocked(args[0]) == null) {
            ui.event("{s} bound to {s} (create it with 'iface add {s}')", .{ args[0], ident, args[0] });
        } else ui.event("{s} bound to {s}; attaches when that agent connects", .{ args[0], ident });
    }

    fn unbind(self: *Console, iface_arg: ?[]const u8) void {
        const name = iface_arg orelse return std.debug.print("usage: unbind <iface>\n", .{});
        self.server.mutex.lock();
        defer self.server.mutex.unlock();
        if (self.server.removeBindingLocked(name)) {
            ui.event("{s} unbound (still attached until 'stop {s}')", .{ name, name });
        } else std.debug.print("{s} has no binding\n", .{name});
    }

    fn listIfaces(self: *Console) void {
        const server = self.server;
        server.mutex.lock();
        defer server.mutex.unlock();
        if (server.tunnels.items.len == 0) std.debug.print("no tunnel interfaces (use 'start' or 'iface add')\n", .{});
        for (server.tunnels.items) |t| {
            if (t.activeSession()) |s| {
                std.debug.print("  {s:<12} agent #{d} ({s}@{s}), {d} flows\n", .{ t.name, s.id, s.user, s.hostname, t.flowCount() });
            } else std.debug.print("  {s:<12} idle\n", .{t.name});
            for (t.routes.items) |r| std.debug.print("      route {s}\n", .{r});
            const st = t.snapshotStats();
            var up: [16]u8 = undefined;
            var down: [16]u8 = undefined;
            std.debug.print("      {d} flows opened, up {s}, down {s}; dials refused {d}, filtered {d}, unreachable {d}\n", .{
                st.flows_opened,  tunnel_mod.fmtBytes(&up, st.bytes_up), tunnel_mod.fmtBytes(&down, st.bytes_down),
                st.dials_refused, st.dials_filtered,                     st.dials_unreachable,
            });
        }
        for (self.pending_routes.items) |r| std.debug.print("  (pending for {s}) route {s}\n", .{ server.default_iface, r });
    }

    fn iface(self: *Console, args: []const []const u8) void {
        const usage_line = "usage: iface add <name> [localhost-net] | iface del <name>\n";
        if (args.len < 2) return std.debug.print(usage_line, .{});
        if (eql(args[0], "add")) {
            const net = if (args.len > 2)
                tun.Cidr.parse(args[2]) catch return std.debug.print("invalid localhost-net '{s}'\n", .{args[2]})
            else
                self.server.default_localhost_net;
            _ = self.createTunnel(args[1], net);
        } else if (eql(args[0], "del")) {
            self.server.deleteTunnel(args[1]) catch |err| return std.debug.print("iface del failed: {s}\n", .{@errorName(err)});
            self.server.mutex.lock();
            _ = self.server.removeBindingLocked(args[1]);
            self.server.mutex.unlock();
            ui.event("deleted {s}", .{args[1]});
        } else std.debug.print(usage_line, .{});
    }

    // ------------------------------------------------------------- routes

    fn addRoute(t: *Tunnel, cidr: []const u8) void {
        t.addRoute(cidr) catch |err| return std.debug.print("route add {s} failed: {s}\n", .{ cidr, @errorName(err) });
        ui.event("routing {s} via {s}", .{ cidr, t.name });
    }

    fn route(self: *Console, args: []const []const u8) void {
        if (args.len == 0 or eql(args[0], "list")) return self.listIfaces();
        if (args.len < 2 or !(eql(args[0], "add") or eql(args[0], "del")))
            return std.debug.print("usage: route add|del <cidr> [iface] [force]\n", .{});
        const net = args[1];
        const cidr = tun.Cidr.parse(net) catch return std.debug.print("invalid cidr '{s}'\n", .{net});
        // Optional trailing words: an interface name and/or "force".
        var name: []const u8 = self.server.default_iface;
        var force = false;
        for (args[2..]) |a| {
            if (eql(a, "force")) force = true else name = a;
        }
        if (eql(args[0], "add") and !force) {
            var buf: [64]u8 = undefined;
            self.server.mutex.lock();
            const covered = self.server.linkCoveredLocked(cidr, &buf);
            self.server.mutex.unlock();
            if (covered) |who| return std.debug.print(
                "refusing: {s} covers {s}; routing it into the tunnel would cut that agent off.\n" ++
                    "Append 'force' to add it anyway.\n",
                .{ net, who },
            );
        }
        const t = self.server.findTunnel(name) orelse {
            if (eql(args[0], "add") and std.mem.eql(u8, name, self.server.default_iface)) {
                self.pending_routes.append(self.gpa, self.gpa.dupe(u8, net) catch return) catch {};
                return std.debug.print("route will be added when {s} is created\n", .{name});
            }
            return std.debug.print("no interface '{s}'\n", .{name});
        };
        if (eql(args[0], "add")) {
            addRoute(t, net);
        } else {
            t.delRoute(net) catch |err| return std.debug.print("route del failed: {s}\n", .{@errorName(err)});
            ui.event("removed {s} from {s}", .{ net, name });
        }
    }

    // ---------------------------------------------------------- listeners

    fn listener(self: *Console, args: []const []const u8) void {
        if (args.len == 0 or eql(args[0], "list")) return self.listListeners();
        if (eql(args[0], "del")) {
            if (args.len < 2) return std.debug.print("usage: listener del <id>\n", .{});
            const id = std.fmt.parseInt(u32, std.mem.trimLeft(u8, args[1], "#"), 10) catch return std.debug.print("invalid id\n", .{});
            self.server.deleteListener(id) catch |err| return std.debug.print("listener del failed: {s}\n", .{@errorName(err)});
            return ui.event("listener #{d} removed", .{id});
        }
        if (!eql(args[0], "add") or args.len < 5)
            return std.debug.print("usage: listener add <agent> <tcp|udp> <bind addr:port> <target addr:port>\n", .{});
        const transport: common.proto.Transport = if (eql(args[2], "tcp")) .tcp else if (eql(args[2], "udp")) .udp else
            return std.debug.print("transport must be tcp or udp\n", .{});
        const bind = std.net.Address.parseIpAndPort(args[3]) catch return std.debug.print("invalid bind address '{s}'\n", .{args[3]});
        const target = std.net.Address.parseIpAndPort(args[4]) catch return std.debug.print("invalid target address '{s}'\n", .{args[4]});
        _ = self.addListener(args[1], transport, bind, target, false);
    }

    fn addListener(self: *Console, agent_arg: ?[]const u8, transport: common.proto.Transport, bind: std.net.Address, target: std.net.Address, is_relay: bool) bool {
        var buf: [64]u8 = undefined;
        const ident = blk: {
            self.server.mutex.lock();
            defer self.server.mutex.unlock();
            break :blk self.resolveIdentLocked(agent_arg, &buf) orelse return false;
        };
        const added = self.server.addListener(ident, transport, bind, target, is_relay) catch |err| {
            std.debug.print("listener add failed: {s}\n", .{@errorName(err)});
            return false;
        };
        if (added.started_on) |sid| {
            ui.event("listener #{d} requested on agent #{d}", .{ added.id, sid });
        } else ui.event("listener #{d} registered; starts when agent {s} connects", .{ added.id, ident });
        return true;
    }

    fn listListeners(self: *Console) void {
        const server = self.server;
        server.mutex.lock();
        defer server.mutex.unlock();
        if (server.listeners.items.len == 0) return std.debug.print("no listeners\n", .{});
        for (server.listeners.items) |l| {
            var where_buf: [32]u8 = undefined;
            const where = if (l.session) |s| std.fmt.bufPrint(&where_buf, "agent #{d}", .{s.id}) catch "?" else "offline";
            std.debug.print("  #{d:<3} {s} ({s}) {s} {f} -> {f}{s}{s}\n", .{
                l.id,
                l.ident,
                where,
                @tagName(l.transport),
                l.bind,
                l.target,
                if (l.is_relay) "  (relay)" else "",
                if (l.active) "" else if (l.session != null) "  (pending)" else "  (waiting for agent)",
            });
        }
    }

    // --------------------------------------------------------- config file

    /// Runs each line of `path` as a console command (blank lines and `#`
    /// comments are skipped). Errors are reported and do not stop the script.
    fn runConfig(self: *Console, path: []const u8) void {
        const data = std.fs.cwd().readFileAlloc(self.gpa, path, 1024 * 1024) catch |err| {
            std.debug.print("cannot read config '{s}': {s}\n", .{ path, @errorName(err) });
            return;
        };
        defer self.gpa.free(data);
        var lines = std.mem.splitScalar(u8, data, '\n');
        var n: usize = 0;
        while (lines.next()) |raw| {
            n += 1;
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            std.debug.print("{s}:{d}> {s}\n", .{ path, n, line });
            self.exec(line);
        }
    }

    /// Writes the current setup as console commands that `-config` replays.
    fn save(self: *Console, path: []const u8) void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        self.writeConfig(&out.writer) catch return std.debug.print("save failed: out of memory\n", .{});
        std.fs.cwd().writeFile(.{ .sub_path = path, .data = out.written() }) catch |err|
            return std.debug.print("cannot write '{s}': {s}\n", .{ path, @errorName(err) });
        std.debug.print("saved to {s} (replay with -config {s})\n", .{ path, path });
    }

    fn writeConfig(self: *Console, w: *std.Io.Writer) !void {
        const server = self.server;
        server.mutex.lock();
        defer server.mutex.unlock();
        try w.writeAll("# zunnel server configuration, written by `save`; load with -config <file>\n");
        for (server.tunnels.items) |t| {
            try w.print("iface add {s} {f}\n", .{ t.name, t.localhost_net });
            for (t.routes.items) |r| try w.print("route add {s} {s}\n", .{ r, t.name });
        }
        for (self.pending_routes.items) |r| try w.print("route add {s} {s}\n", .{ r, server.default_iface });
        for (server.bindings.items) |b| try w.print("bind {s} {s}\n", .{ b.iface, b.ident });
        for (server.listeners.items) |l| {
            if (l.is_relay) {
                try w.print("relay {s} {f}\n", .{ l.ident, l.bind });
            } else try w.print("listener add {s} {s} {f} {f}\n", .{ l.ident, @tagName(l.transport), l.bind, l.target });
        }
    }

    fn relay(self: *Console, agent_arg: ?[]const u8, bind_arg: ?[]const u8) void {
        const bind = if (bind_arg) |b|
            std.net.Address.parseIpAndPort(b) catch return std.debug.print("invalid bind address '{s}'\n", .{b})
        else
            std.net.Address.initIp4(.{ 0, 0, 0, 0 }, common.proto.default_port);
        if (!self.addListener(agent_arg, .tcp, bind, self.server.relayTarget(), true)) return;
        std.debug.print("deeper agents can now run: zunnel-agent -connect <agent-ip>:{d} -pubkey <this server's key>\n", .{bind.getPort()});
    }
};

fn at(args: []const []const u8, i: usize) ?[]const u8 {
    return if (i < args.len) args[i] else null;
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

test {
    _ = @import("packet.zig");
    _ = @import("tun.zig");
    _ = @import("lineedit.zig");
    _ = @import("tunnel.zig");
    _ = @import("tls.zig");
    _ = @import("reassemble.zig");
}
