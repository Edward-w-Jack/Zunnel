//! zunnel-proxy: runs on the operator machine. Accepts agents, exposes TUN
//! interfaces routed through them, and manages listeners on the agents.
const std = @import("std");
const builtin = @import("builtin");
const common = @import("common");
const privileges = @import("privileges.zig");
const tun = @import("tun.zig");
const server_mod = @import("server.zig");
const Tunnel = @import("tunnel.zig").Tunnel;

const Server = server_mod.Server;
const Session = server_mod.Session;
const keys = common.keys;
const Allocator = std.mem.Allocator;

pub const std_options: std.Options = .{ .log_level = .info };

const usage =
    \\usage: zunnel-proxy [options]
    \\
    \\  -listen <addr:port>  address agents connect to (default 0.0.0.0:11601)
    \\  -key <file>          proxy private key, created if missing (default zunnel.key)
    \\  -secret <secret>     shared secret agents must present (recommended)
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
    secret: []const u8 = "",
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

    const static, const created = keys.loadOrCreate(opts.key_file) catch |err|
        fatal("cannot load key file '{s}': {s}", .{ opts.key_file, @errorName(err) });
    if (created) std.debug.print("generated new key in {s}\n", .{opts.key_file});
    const pubkey = keys.encode(static.public_key);

    var server: Server = .{
        .gpa = gpa,
        .static = static,
        .psk = common.noise.pskFromSecret(opts.secret),
        .autostart = opts.autostart,
        .listen_address = opts.listen,
        .default_iface = opts.tun_name,
        .default_localhost_net = opts.localhost_net,
        .dial_timeout_ms = opts.dial_timeout_ms,
        .max_dials = opts.max_dials,
    };
    var console: Console = .{ .gpa = gpa, .server = &server, .pending_routes = opts.routes };
    installShutdownHandlers(&server);
    if (opts.autostart) _ = console.ensureTunnel(opts.tun_name) orelse std.process.exit(1);

    server.listen() catch |err| fatal("cannot listen on {f}: {s}", .{ opts.listen, @errorName(err) });

    std.debug.print(
        \\zunnel proxy {s} listening on {f}
        \\public key: {s}
        \\agent:      zunnel-agent -connect <this-host>:{d} -pubkey {s}{s}{s}
        \\type 'help' for commands
        \\
    , .{
        common.version,        opts.listen, &pubkey,
        opts.listen.getPort(), &pubkey,     if (opts.secret.len > 0) " -secret " else "",
        if (opts.secret.len > 0) "<secret>" else "",
    });
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
    std.debug.print("\nshutting down...\n", .{});
    if (shutdown_server) |s| s.shutdown();
    std.process.exit(0);
}

fn onSignal(_: c_int) callconv(.c) void {
    stop_requested.store(true, .release);
}

fn shutdownWatcher() void {
    while (!stop_requested.load(.acquire)) std.Thread.sleep(100 * std.time.ns_per_ms);
    std.debug.print("\nshutting down...\n", .{});
    if (shutdown_server) |s| s.shutdown();
    std.process.exit(0);
}

const help_text =
    \\  sessions                                   list connected agents
    \\  start [agent] [iface]                      route an interface through an agent
    \\                                             (creates the interface if needed)
    \\  stop [iface]                               detach the agent from an interface
    \\  ifaces                                     list tunnel interfaces and routes
    \\  iface add <name> [localhost-net]           create a tunnel interface
    \\  iface del <name>                           delete a tunnel interface
    \\  route add <cidr> [iface]                   route a network through an interface
    \\  route del <cidr> [iface]                   remove a route
    \\  listener add <agent> <tcp|udp> <bind> <target>
    \\                                             listen on the agent; connections are
    \\                                             forwarded to <target>, dialed by the proxy
    \\  listener del <id>                          remove a listener
    \\  listeners                                  list listeners
    \\  relay <agent> [bind]                       let deeper agents connect through
    \\                                             <agent> (default bind 0.0.0.0:11601)
    \\  kill <agent>                               shut an agent down for good (no reconnect)
    \\  exit                                       quit
    \\
    \\  [iface] defaults to the -tun name; [agent] defaults to the only agent.
    \\  <agent> is a session number or a unique prefix of the agent's IDENT.
    \\
;

const Console = struct {
    gpa: Allocator,
    server: *Server,
    /// -route values for the default interface, applied when it is created.
    pending_routes: std.ArrayList([]const u8) = .empty,

    fn run(self: *Console) void {
        var buf: [1024]u8 = undefined;
        var reader = std.fs.File.stdin().reader(&buf);
        while (true) {
            std.debug.print("zunnel> ", .{});
            const line = reader.interface.takeDelimiter('\n') catch break orelse break;
            self.exec(std.mem.trim(u8, line, " \t\r"));
        }
        // stdin closed (e.g. running as a service): keep serving.
        while (true) std.Thread.sleep(std.time.ns_per_hour);
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
        } else if (eql(cmd, "exit") or eql(cmd, "quit")) {
            self.server.shutdown();
            std.process.exit(0);
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

    /// Tells an agent to shut down for good; it will not reconnect.
    fn kill(self: *Console, agent_arg: ?[]const u8) void {
        const arg = agent_arg orelse return std.debug.print("usage: kill <agent>\n", .{});
        self.server.mutex.lock();
        defer self.server.mutex.unlock();
        const s = self.resolveAgentLocked(arg) orelse return;
        s.link.send(.kill, 0, &.{}) catch return std.debug.print("agent #{d} is already disconnecting\n", .{s.id});
        std.debug.print("sent kill to agent #{d} ({s}@{s}); it will not reconnect\n", .{ s.id, s.user, s.hostname });
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
        std.debug.print("created tunnel interface {s}\n", .{name});
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
        std.debug.print("tunnel {s} now routes through agent #{d} ({s}@{s})\n", .{ name, s.id, s.user, s.hostname });
    }

    fn stop(self: *Console, name: []const u8) void {
        self.server.mutex.lock();
        defer self.server.mutex.unlock();
        const t = self.server.findTunnelLocked(name) orelse return std.debug.print("no interface '{s}'\n", .{name});
        const s = t.activeSession() orelse return std.debug.print("{s} has no agent\n", .{name});
        _ = t.detach(s);
        std.debug.print("{s} stopped\n", .{name});
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
            std.debug.print("deleted {s}\n", .{args[1]});
        } else std.debug.print(usage_line, .{});
    }

    // ------------------------------------------------------------- routes

    fn addRoute(t: *Tunnel, cidr: []const u8) void {
        t.addRoute(cidr) catch |err| return std.debug.print("route add {s} failed: {s}\n", .{ cidr, @errorName(err) });
        std.debug.print("routing {s} via {s}\n", .{ cidr, t.name });
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
            std.debug.print("removed {s} from {s}\n", .{ net, name });
        }
    }

    // ---------------------------------------------------------- listeners

    fn listener(self: *Console, args: []const []const u8) void {
        if (args.len == 0 or eql(args[0], "list")) return self.listListeners();
        if (eql(args[0], "del")) {
            if (args.len < 2) return std.debug.print("usage: listener del <id>\n", .{});
            const id = std.fmt.parseInt(u32, std.mem.trimLeft(u8, args[1], "#"), 10) catch return std.debug.print("invalid id\n", .{});
            self.server.deleteListener(id) catch |err| return std.debug.print("listener del failed: {s}\n", .{@errorName(err)});
            return std.debug.print("listener #{d} removed\n", .{id});
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
        const agent_id = blk: {
            self.server.mutex.lock();
            defer self.server.mutex.unlock();
            break :blk (self.resolveAgentLocked(agent_arg) orelse return false).id;
        };
        const id = self.server.addListener(agent_id, transport, bind, target, is_relay) catch |err| {
            std.debug.print("listener add failed: {s}\n", .{@errorName(err)});
            return false;
        };
        std.debug.print("listener #{d} requested on agent #{d}\n", .{ id, agent_id });
        return true;
    }

    fn listListeners(self: *Console) void {
        const server = self.server;
        server.mutex.lock();
        defer server.mutex.unlock();
        if (server.listeners.items.len == 0) return std.debug.print("no listeners\n", .{});
        for (server.listeners.items) |l| {
            std.debug.print("  #{d:<3} agent #{d:<3} {s} {f} -> {f}{s}{s}\n", .{
                l.id,
                l.session.id,
                @tagName(l.transport),
                l.bind,
                l.target,
                if (l.is_relay) "  (relay)" else "",
                if (l.active) "" else "  (pending)",
            });
        }
    }

    fn relay(self: *Console, agent_arg: ?[]const u8, bind_arg: ?[]const u8) void {
        const bind = if (bind_arg) |b|
            std.net.Address.parseIpAndPort(b) catch return std.debug.print("invalid bind address '{s}'\n", .{b})
        else
            std.net.Address.initIp4(.{ 0, 0, 0, 0 }, common.proto.default_port);
        if (!self.addListener(agent_arg, .tcp, bind, self.server.relayTarget(), true)) return;
        std.debug.print("deeper agents can now run: zunnel-agent -connect <agent-ip>:{d} -pubkey <this proxy's key>\n", .{bind.getPort()});
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
}
