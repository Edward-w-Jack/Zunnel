const std = @import("std");

/// lwIP core sources we compile unmodified (relative to lwip/src/core).
const lwip_core_files = [_][]const u8{
    "init.c",       "def.c",         "inet_chksum.c", "ip.c",
    "mem.c",        "memp.c",        "netif.c",       "pbuf.c",
    "stats.c",      "sys.c",         "tcp.c",         "tcp_out.c",
    "timeouts.c",   "udp.c",         "raw.c",         "ipv4/ip4_addr.c",
    "ipv4/icmp.c",  "ipv4/ip4_frag.c",
};

/// lwIP sources that are patched at build time so the stack accepts traffic for
/// *any* destination address/port (the "tun2socks" trick). Each patch is an
/// exact, single-occurrence find/replace; the patch tool fails loudly if lwIP
/// changes underneath us.
const LwipPatch = struct {
    file: []const u8,
    out: []const u8,
    edits: []const [2][]const u8,
};

const lwip_patches = [_]LwipPatch{
    .{
        .file = "ipv4/ip4.c",
        .out = "ip4.c",
        .edits = &.{
            // Accept every destination address arriving on the TUN netif.
            .{ "if (ip4_input_accept(inp)) {", "if (netif_is_up(inp)) { /* zunnel: accept all destinations */" },
        },
    },
    .{
        .file = "tcp_in.c",
        .out = "tcp_in.c",
        .edits = &.{
            // A single wildcard listener matches every destination port...
            .{ "if (lpcb->local_port == tcphdr->dest) {", "if (1) { /* zunnel: wildcard listener */" },
            // ...and accepted pcbs keep the port the client actually dialed.
            .{ "npcb->local_port = pcb->local_port;", "npcb->local_port = tcphdr->dest; /* zunnel */" },
        },
    },
};

const lwip_cflags = [_][]const u8{
    "-std=c99",
    "-fno-sanitize=undefined",
    "-Wno-unused-but-set-variable",
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // `zig build -Drelease` builds ReleaseSafe: both binaries parse untrusted
    // network input, so keep bounds/overflow checks in release builds.
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });
    const strip = b.option(bool, "strip", "Strip debug info from binaries") orelse (optimize != .Debug);

    const common = b.createModule(.{
        .root_source_file = b.path("src/common/common.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ---------------------------------------------------------------- agent
    // Settings baked into the agent so it runs without arguments. Flags and
    // ZUNNEL_* environment variables still override them.
    const agent_opts = b.addOptions();
    agent_opts.addOption(?[]const u8, "connect", b.option([]const u8, "agent-connect", "Bake in the proxy address (host:port)"));
    agent_opts.addOption(?[]const u8, "pubkey", b.option([]const u8, "agent-pubkey", "Bake in the proxy public key"));
    agent_opts.addOption(?[]const u8, "secret", b.option([]const u8, "agent-secret", "Bake in the shared secret"));
    agent_opts.addOption(?[]const u8, "expire", b.option([]const u8, "agent-expire", "Bake in an expiry (UTC time or duration)"));
    agent_opts.addOption(?[]const u8, "id", b.option([]const u8, "agent-id", "Bake in an agent id (default: derived from the host)"));
    agent_opts.addOption(?bool, "retry", b.option(bool, "agent-retry", "Reconnect forever (default: on when -Dagent-connect is set)"));

    const agent_mod = b.createModule(.{
        .root_source_file = b.path("src/agent/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
        .imports = &.{
            .{ .name = "common", .module = common },
            .{ .name = "agent_options", .module = agent_opts.createModule() },
        },
    });
    const agent = b.addExecutable(.{ .name = "zunnel-agent", .root_module = agent_mod });
    b.installArtifact(agent);

    // ----------------------------------------------------------------- lwIP
    const lwip_dep = b.dependency("lwip", .{});
    const lwip = b.addLibrary(.{
        .name = "lwip",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    lwip.root_module.addIncludePath(b.path("src/lwip"));
    lwip.root_module.addIncludePath(lwip_dep.path("src/include"));
    lwip.root_module.addCSourceFiles(.{
        .root = lwip_dep.path("src/core"),
        .files = &lwip_core_files,
        .flags = &lwip_cflags,
    });

    const patcher = b.addExecutable(.{
        .name = "lwip-patch",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/patch.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });
    for (lwip_patches) |patch| {
        const run = b.addRunArtifact(patcher);
        run.addFileArg(lwip_dep.path(b.fmt("src/core/{s}", .{patch.file})));
        const patched = run.addOutputFileArg(patch.out);
        for (patch.edits) |edit| run.addArgs(&edit);
        lwip.root_module.addCSourceFile(.{ .file = patched, .flags = &lwip_cflags });
    }

    // ---------------------------------------------------------------- proxy
    const proxy_mod = b.createModule(.{
        .root_source_file = b.path("src/proxy/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
        .link_libc = true,
        .imports = &.{.{ .name = "common", .module = common }},
    });
    proxy_mod.addIncludePath(b.path("src/lwip"));
    proxy_mod.addIncludePath(lwip_dep.path("src/include"));
    proxy_mod.linkLibrary(lwip);
    const proxy = b.addExecutable(.{ .name = "zunnel-proxy", .root_module = proxy_mod });
    b.installArtifact(proxy);

    // ------------------------------------------------------------- run/test
    const run_proxy = b.addRunArtifact(proxy);
    const run_agent = b.addRunArtifact(agent);
    if (b.args) |args| {
        run_proxy.addArgs(args);
        run_agent.addArgs(args);
    }
    b.step("proxy", "Run the proxy").dependOn(&run_proxy.step);
    b.step("agent", "Run the agent").dependOn(&run_agent.step);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = common })).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = proxy_mod })).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = agent_mod })).step);

    // Zig 0.15's fuzzer cannot instrument the proxy test binary (it links libc
    // and lwIP), so fuzzing gets its own step with only pure-Zig parsers:
    // `zig build fuzz --fuzz` (Linux). Without --fuzz it runs the tests once.
    const packet_mod = b.createModule(.{
        .root_source_file = b.path("src/proxy/packet.zig"),
        .target = target,
        .optimize = optimize,
    });
    const fuzz_step = b.step("fuzz", "Fuzz the untrusted-input parsers (use with --fuzz, Linux only)");
    fuzz_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = common })).step);
    fuzz_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = packet_mod })).step);
}
