//! Listeners opened on the agent at the server's request. Every accepted TCP
//! connection / UDP source address becomes a relay flow announced with
//! `accepted`; the server dials the listener's target on its side.
const std = @import("std");
const common = @import("common");

const clock = common.clock;
const proto = common.proto;
const sock = common.sock;
const relay = common.relay;
const log = std.log.scoped(.listener);

pub const Listener = struct {
    gpa: std.mem.Allocator,
    table: *relay.Table,
    id: u32,
    transport: proto.Transport,
    handle: sock.Handle,
    stopping: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,

    pub fn start(gpa: std.mem.Allocator, table: *relay.Table, id: u32, bind: proto.Endpoint) !*Listener {
        const addr = proto.endpointAddress(bind);
        const handle = switch (bind.transport) {
            .tcp => (try sock.listenTcp(addr, 128)).stream.handle,
            .udp => try sock.udpBind(addr),
            _ => return error.UnsupportedTransport,
        };
        errdefer sock.close(handle);
        const self = try gpa.create(Listener);
        errdefer gpa.destroy(self);
        self.* = .{ .gpa = gpa, .table = table, .id = id, .transport = bind.transport, .handle = handle };
        const cfg: std.Thread.SpawnConfig = .{ .stack_size = 256 * 1024 };
        self.thread = if (bind.transport == .tcp)
            try std.Thread.spawn(cfg, tcpLoop, .{self})
        else
            try std.Thread.spawn(cfg, udpLoop, .{self});
        return self;
    }

    /// Stops accepting, ends UDP associations and frees the listener.
    /// Accepted TCP connections keep running.
    pub fn stop(self: *Listener) void {
        self.stopping.store(true, .release);
        self.thread.join();
        sock.close(self.handle);
        self.gpa.destroy(self);
    }

    fn announce(self: *Listener, flow_id: u32, peer: std.net.Address) void {
        var storage: [16]u8 = undefined;
        var buf: [proto.Accepted.max_len]u8 = undefined;
        const msg: proto.Accepted = .{ .listener_id = self.id, .peer = proto.addressEndpoint(self.transport, peer, &storage) };
        self.table.link.send(.accepted, flow_id, msg.encode(&buf)) catch {};
    }

    fn tcpLoop(self: *Listener) void {
        var server: std.net.Server = .{ .listen_address = undefined, .stream = .{ .handle = self.handle } };
        while (!self.stopping.load(.acquire)) {
            if (!sock.pollRead(self.handle, 500)) continue;
            const conn = server.accept() catch |err| {
                log.warn("listener {d}: accept failed: {s}", .{ self.id, @errorName(err) });
                std.Thread.sleep(100 * std.time.ns_per_ms);
                continue;
            };
            sock.setNoDelay(conn.stream.handle);
            const flow_id = self.table.adoptTcp(conn.stream.handle) orelse continue;
            self.announce(flow_id, conn.address);
        }
    }

    const Assoc = struct { peer: std.net.Address, flow: *relay.Flow };

    fn udpLoop(self: *Listener) void {
        var assocs: std.ArrayList(Assoc) = .empty;
        defer {
            for (assocs.items) |a| a.flow.detachListener(true);
            assocs.deinit(self.gpa);
        }
        var buf: [proto.max_payload]u8 = undefined;
        var last_sweep = clock.monotonicMs();

        while (!self.stopping.load(.acquire)) {
            if (clock.monotonicMs() - last_sweep >= 1000) {
                last_sweep = clock.monotonicMs();
                var i: usize = 0;
                while (i < assocs.items.len) {
                    const f = assocs.items[i].flow;
                    if (f.isAborted() or f.idleMs() > relay.udp_idle_ms) {
                        f.detachListener(!f.isAborted());
                        _ = assocs.swapRemove(i);
                    } else i += 1;
                }
            }
            if (!sock.pollRead(self.handle, 500)) continue;
            const n, const peer = sock.recvFrom(self.handle, &buf) catch continue;

            const flow = for (assocs.items, 0..) |a, i| {
                if (!a.peer.eql(peer)) continue;
                if (!a.flow.isAborted()) break a.flow;
                a.flow.detachListener(false);
                _ = assocs.swapRemove(i);
                break null;
            } else null;
            const f = flow orelse blk: {
                const nf = self.table.adoptUdp(self.handle, peer) orelse continue;
                assocs.append(self.gpa, .{ .peer = peer, .flow = nf }) catch {
                    nf.detachListener(false);
                    continue;
                };
                self.announce(nf.id, peer);
                break :blk nf;
            };
            f.touch();
            self.table.link.sendDroppable(.data, f.id, buf[0..n]) catch {};
        }
    }
};
