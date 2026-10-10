//! The encrypted, framed connection between proxy and agent.
//!
//! Handshake on a fresh connection (over whatever `Stream` the caller passes:
//! raw TCP, or TLS as of ZNL6). The agent speaks first — no cleartext bytes
//! leave the proxy until it has read a valid message 1:
//!   agent -> proxy : u16be len | Noise message 1 (payload: agent hello)
//!   proxy -> agent : u16be len | Noise message 2
//!
//! The protocol version is mixed into the Noise prologue, so a mismatch fails
//! the AEAD tag like a wrong secret would.
//!
//! Afterwards each record is `u16be len | ciphertext` and decrypts to:
//!   real_len u16be | frames[real_len] | pad[plain_len - 2 - real_len]
//! The sender pads every record up to the next `record_bucket` multiple with
//! random bytes, so sizes on the wire don't reveal frame boundaries.
//!
//! Sending never blocks the caller: frames are queued and a dedicated writer
//! thread encrypts and writes them.
const std = @import("std");
const clock = @import("clock.zig");
const noise = @import("noise.zig");
const proto = @import("proto.zig");
const sock = @import("sock.zig");
const stream_mod = @import("stream.zig");

const Stream = stream_mod.Stream;

const Allocator = std.mem.Allocator;
const log = std.log.scoped(.link);

/// Record plaintext layout: 2 bytes of real-content length, then the frames,
/// then padding to the next `record_bucket` multiple. The on-wire record is
/// `u16be len | ciphertext`, so `max_record` tops out just under 2^16 to fit
/// a `u16be` length prefix. The plaintext budget is `max_record - tag_len`.
const max_record_plain = 65_535 - noise.tag_len;
const max_frames_plain = max_record_plain - 2;
const max_record = max_record_plain + noise.tag_len;
/// Every record on the wire (ciphertext + 2-byte length prefix) is at least
/// this big, so record sizes don't reveal frame boundaries.
const record_bucket = 512;
const max_hello = 4096;
const handshake_timeout_ms = 10_000;
/// Droppable (UDP) frames are discarded once this much is queued.
const soft_queue_limit = 8 * 1024 * 1024;

pub const Frame = struct {
    type: proto.FrameType,
    id: u32,
    payload: []const u8,
};

pub const Link = struct {
    gpa: Allocator,
    stream: Stream,
    tx: noise.CipherState,
    rx: noise.CipherState,

    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    queue: std.ArrayList(u8) = .empty,
    closed: bool = false,
    writer: ?std.Thread = null,
    /// When the last record arrived (clock.monotonicMs); the writer closes the
    /// link when it goes stale.
    last_rx: std.atomic.Value(i64) = .init(0),
    /// Bytes on the wire (records, including encryption overhead).
    bytes_tx: std.atomic.Value(u64) = .init(0),
    bytes_rx: std.atomic.Value(u64) = .init(0),

    rx_buf: [max_record]u8 = undefined,
    rx_pos: usize = 0,
    rx_len: usize = 0,

    fn create(gpa: Allocator, s: Stream, t: noise.Transport) !*Link {
        const self = try gpa.create(Link);
        self.* = .{ .gpa = gpa, .stream = s, .tx = t.send, .rx = t.recv };
        self.last_rx.store(clock.monotonicMs(), .monotonic);
        errdefer gpa.destroy(self);
        // A peer that stops reading for this long is as dead as a silent one.
        s.setSendTimeout(proto.link_dead_after_ms);
        self.writer = try std.Thread.spawn(.{}, writerLoop, .{self});
        return self;
    }

    /// Closes the link (if needed), waits for the writer and frees everything.
    /// No other thread may be using the link anymore.
    pub fn destroy(self: *Link) void {
        self.close();
        if (self.writer) |t| t.join();
        self.queue.deinit(self.gpa);
        self.stream.close();
        self.gpa.destroy(self);
    }

    /// Idempotent; unblocks the reader (with an error) and stops the writer.
    pub fn close(self: *Link) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.closeLocked();
    }

    fn closeLocked(self: *Link) void {
        if (self.closed) return;
        self.closed = true;
        self.stream.shutdown(.both);
        self.cond.broadcast();
    }

    pub fn isClosed(self: *Link) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.closed;
    }

    pub fn send(self: *Link, ftype: proto.FrameType, id: u32, payload: []const u8) error{ Closed, OutOfMemory }!void {
        return self.enqueue(ftype, id, payload, false);
    }

    /// Like send, but silently drops the frame when the queue is congested.
    pub fn sendDroppable(self: *Link, ftype: proto.FrameType, id: u32, payload: []const u8) error{ Closed, OutOfMemory }!void {
        return self.enqueue(ftype, id, payload, true);
    }

    pub fn sendWindow(self: *Link, id: u32, credit: u32) error{ Closed, OutOfMemory }!void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, credit, .big);
        return self.send(.window, id, &b);
    }

    fn enqueue(self: *Link, ftype: proto.FrameType, id: u32, payload: []const u8, droppable: bool) error{ Closed, OutOfMemory }!void {
        std.debug.assert(payload.len <= proto.max_payload);
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.closed) return error.Closed;
        if (droppable and self.queue.items.len > soft_queue_limit) return;
        try self.enqueueLocked(ftype, id, payload);
    }

    fn enqueueLocked(self: *Link, ftype: proto.FrameType, id: u32, payload: []const u8) error{OutOfMemory}!void {
        var hdr: [proto.header_len]u8 = undefined;
        proto.writeHeader(&hdr, ftype, id, @intCast(payload.len));
        try self.queue.ensureUnusedCapacity(self.gpa, hdr.len + payload.len);
        self.queue.appendSliceAssumeCapacity(&hdr);
        self.queue.appendSliceAssumeCapacity(payload);
        self.cond.signal();
    }

    fn writerLoop(self: *Link) void {
        var batch: std.ArrayList(u8) = .empty;
        defer batch.deinit(self.gpa);
        const out = self.gpa.alloc(u8, 2 + max_record) catch {
            self.close();
            return;
        };
        defer self.gpa.free(out);

        var last_ping = clock.monotonicMs();
        while (true) {
            {
                self.mutex.lock();
                defer self.mutex.unlock();
                while (true) {
                    if (self.closed) return;
                    // Heartbeat: both ends ping; whatever arrives refreshes last_rx.
                    const now = clock.monotonicMs();
                    if (now - self.last_rx.load(.monotonic) > proto.link_dead_after_ms) {
                        log.warn("link timed out: nothing received for {d}s", .{@divTrunc(proto.link_dead_after_ms, 1000)});
                        self.closeLocked();
                        return;
                    }
                    if (now - last_ping >= proto.heartbeat_interval_ms) {
                        last_ping = now;
                        var ts: [8]u8 = undefined;
                        std.mem.writeInt(i64, &ts, now, .big);
                        self.enqueueLocked(.ping, 0, &ts) catch {};
                    }
                    if (self.queue.items.len > 0) break;
                    self.cond.timedWait(&self.mutex, std.time.ns_per_s) catch {};
                }
                std.mem.swap(std.ArrayList(u8), &self.queue, &batch);
            }

            // Pack whole frames into records of at most max_frames_plain bytes;
            // every record is padded on the wire up to the next record_bucket.
            // `plain_buf` is 2 bytes of real-length + frames + random padding.
            var plain_buf: [max_record_plain]u8 = undefined;
            var off: usize = 0;
            while (off < batch.items.len) {
                var end = off;
                while (end < batch.items.len) {
                    const h = proto.parseHeader(batch.items[end..][0..proto.header_len]);
                    const flen = proto.header_len + @as(usize, h.len);
                    if (end > off and end + flen - off > max_frames_plain) break;
                    end += flen;
                }
                const real_len = end - off;
                std.mem.writeInt(u16, plain_buf[0..2], @intCast(real_len), .big);
                @memcpy(plain_buf[2..][0..real_len], batch.items[off..end]);
                const plain_len = paddedPlainLen(real_len);
                std.crypto.random.bytes(plain_buf[2 + real_len .. plain_len]);
                const ct_len = plain_len + noise.tag_len;
                std.mem.writeInt(u16, out[0..2], @intCast(ct_len), .big);
                self.tx.encrypt(out[2..][0..ct_len], "", plain_buf[0..plain_len]) catch {
                    self.close();
                    return;
                };
                self.stream.sendAll(out[0 .. 2 + ct_len]) catch {
                    self.close();
                    return;
                };
                _ = self.bytes_tx.fetchAdd(@as(u64, 2) + ct_len, .monotonic);
                off = end;
            }
            batch.clearRetainingCapacity();
            if (batch.capacity > 4 * 1024 * 1024) batch.clearAndFree(self.gpa);
        }
    }

    /// Returns the next frame. The payload is valid until the next call.
    /// Only one thread may read from a link.
    pub fn recvFrame(self: *Link) !Frame {
        if (self.rx_pos >= self.rx_len) try self.readRecord();
        const frame, const used = try parseFrame(self.rx_buf[self.rx_pos..self.rx_len]);
        self.rx_pos += used;
        return frame;
    }

    fn readRecord(self: *Link) !void {
        var lb: [2]u8 = undefined;
        try self.stream.recvExact(&lb);
        const len = std.mem.readInt(u16, &lb, .big);
        if (len <= noise.tag_len + 2 or len > max_record) return error.InvalidMessage;
        try self.stream.recvExact(self.rx_buf[0..len]);
        const plain_len = len - noise.tag_len;
        try self.rx.decrypt(self.rx_buf[0..plain_len], "", self.rx_buf[0..len]);
        // Plaintext: real_len u16be | frames | pad. Padding is ignored.
        const real_len = std.mem.readInt(u16, self.rx_buf[0..2], .big);
        if (real_len > plain_len - 2) return error.InvalidMessage;
        self.rx_pos = 2;
        self.rx_len = 2 + real_len;
        self.last_rx.store(clock.monotonicMs(), .monotonic);
        _ = self.bytes_rx.fetchAdd(@as(u64, 2) + len, .monotonic);
    }
};

/// Rounds `real_len + 2` up to the next `record_bucket` multiple, clamped to
/// `max_record_plain`.
fn paddedPlainLen(real_len: usize) usize {
    const want = 2 + real_len;
    const rounded = (want + record_bucket - 1) / record_bucket * record_bucket;
    return @min(rounded, max_record_plain);
}

test paddedPlainLen {
    try std.testing.expectEqual(@as(usize, record_bucket), paddedPlainLen(0));
    try std.testing.expectEqual(@as(usize, record_bucket), paddedPlainLen(1));
    try std.testing.expectEqual(@as(usize, record_bucket), paddedPlainLen(record_bucket - 2));
    try std.testing.expectEqual(@as(usize, 2 * record_bucket), paddedPlainLen(record_bucket - 1));
    try std.testing.expectEqual(@as(usize, max_record_plain), paddedPlainLen(max_frames_plain));
}

/// Parses the frame at the start of `buf` (decrypted record contents) and
/// returns it with the number of bytes it occupies. The payload aliases `buf`.
pub fn parseFrame(buf: []const u8) error{InvalidMessage}!struct { Frame, usize } {
    if (buf.len < proto.header_len) return error.InvalidMessage;
    const h = proto.parseHeader(buf[0..proto.header_len]);
    const total = proto.header_len + @as(usize, h.len);
    if (buf.len < total) return error.InvalidMessage;
    return .{ .{ .type = h.type, .id = h.id, .payload = buf[proto.header_len..total] }, total };
}

test parseFrame {
    var buf: [proto.header_len + 3]u8 = undefined;
    proto.writeHeader(buf[0..proto.header_len], .data, 42, 3);
    buf[proto.header_len..].* = "abc".*;
    const frame, const used = try parseFrame(&buf);
    try std.testing.expectEqual(proto.FrameType.data, frame.type);
    try std.testing.expectEqual(@as(u32, 42), frame.id);
    try std.testing.expectEqualStrings("abc", frame.payload);
    try std.testing.expectEqual(buf.len, used);
    try std.testing.expectError(error.InvalidMessage, parseFrame(buf[0 .. buf.len - 1]));
}

test "fuzz parseFrame" {
    try std.testing.fuzz({}, struct {
        fn one(_: void, input: []const u8) anyerror!void {
            // Walk the input as a record: every frame must stay inside it.
            var rest = input;
            while (rest.len > 0) {
                const frame, const used = parseFrame(rest) catch return;
                try std.testing.expect(used >= proto.header_len and used <= rest.len);
                try std.testing.expect(frame.payload.len == used - proto.header_len);
                rest = rest[used..];
            }
        }
    }.one, .{ .corpus = &.{
        &.{ 6, 0, 0, 0, 0, 1, 0, 2, 'h', 'i' },
        &.{ 1, 0, 0, 0, 0, 0, 0, 0 },
        &.{ 9, 0, 255, 255, 255, 255, 255, 255 },
    } });
}

fn sendMsg(s: Stream, msg: []const u8) !void {
    var lb: [2]u8 = undefined;
    std.mem.writeInt(u16, &lb, @intCast(msg.len), .big);
    try s.sendAll(&lb);
    try s.sendAll(msg);
}

fn recvMsg(s: Stream, buf: []u8) ![]u8 {
    var lb: [2]u8 = undefined;
    try s.recvExact(&lb);
    const len = std.mem.readInt(u16, &lb, .big);
    if (len > buf.len) return error.InvalidMessage;
    try s.recvExact(buf[0..len]);
    return buf[0..len];
}

pub const ClientResult = struct { link: *Link };

/// Agent side. The agent speaks first — nothing is received before the
/// agent's message 1 is sent — so the stream carries no cleartext bytes from
/// the proxy that could identify the protocol. `server_key` must match the
/// proxy's static key, otherwise message 2 fails with `AuthenticationFailed`.
/// On success the link owns `s`.
pub fn clientHandshake(
    gpa: Allocator,
    s: Stream,
    server_key: [noise.key_len]u8,
    psk: [noise.key_len]u8,
    hello: []const u8,
) !ClientResult {
    s.setRecvTimeout(handshake_timeout_ms);
    var hs = noise.Initiator.init(server_key, psk, proto.prologue);
    var buf: [max_hello + 64]u8 = undefined;
    try sendMsg(s, try hs.writeMessage1(&buf, hello[0..@min(hello.len, max_hello)]));

    var payload: [64]u8 = undefined;
    const msg2 = try recvMsg(s, &buf);
    const transport, _ = try hs.readMessage2(msg2, &payload);
    s.setRecvTimeout(0);
    return .{ .link = try Link.create(gpa, s, transport) };
}

pub const ServerResult = struct {
    link: *Link,
    hello: []u8,
};

/// Proxy side. On success the link owns `s` and `hello` points into `hello_buf`.
pub fn serverHandshake(
    gpa: Allocator,
    s: Stream,
    static: noise.KeyPair,
    psk: [noise.key_len]u8,
    hello_buf: *[max_hello]u8,
) !ServerResult {
    s.setRecvTimeout(handshake_timeout_ms);
    var hs = noise.Responder.init(static, psk, proto.prologue);
    var buf: [max_hello + 64]u8 = undefined;
    const msg1 = try recvMsg(s, &buf);
    const hello = try hs.readMessage1(msg1, hello_buf);

    var out: [64]u8 = undefined;
    const transport, const msg2 = try hs.writeMessage2(&out, "");
    try sendMsg(s, msg2);
    s.setRecvTimeout(0);
    return .{ .link = try Link.create(gpa, s, transport), .hello = hello };
}

pub const max_hello_len = max_hello;

// --------------------------------------------------------------------- tests

/// One side of a loopback TCP pair used by the ZNL6 handshake tests.
const PairSide = struct {
    stream: Stream,
    handle: sock.Handle,
};

/// A loopback TCP pair wrapped in TcpStream, so a handshake test can run both
/// ends of the link on real sockets.
fn loopbackPair(gpa: Allocator) !struct { PairSide, PairSide } {
    var listener = try sock.listenTcp(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0), 1);
    defer listener.deinit();
    const client_handle = try sock.tcpConnect(listener.listen_address, 2000);
    errdefer sock.close(client_handle);
    const srv_conn = try listener.accept();
    errdefer srv_conn.stream.close();
    const client_stream = try stream_mod.TcpStream.wrap(gpa, client_handle);
    errdefer client_stream.close();
    const server_stream = try stream_mod.TcpStream.wrap(gpa, srv_conn.stream.handle);
    return .{
        .{ .stream = client_stream, .handle = client_handle },
        .{ .stream = server_stream, .handle = srv_conn.stream.handle },
    };
}

const HandshakeFixture = struct {
    static: noise.KeyPair,
    psk: [noise.key_len]u8,
    gpa: Allocator,

    fn serve(self: *@This(), s: Stream, out: *?*Link) void {
        var hello_buf: [max_hello]u8 = undefined;
        const res = serverHandshake(self.gpa, s, self.static, self.psk, &hello_buf) catch {
            s.close();
            return;
        };
        out.* = res.link;
    }
};

test "a max-size UDP-ish frame survives the record layer" {
    const gpa = std.testing.allocator;
    const static = noise.KeyPair.generate();
    const psk = noise.pskFromSecret("s");
    const client, const server = try loopbackPair(gpa);
    var server_link: ?*Link = null;
    var fx: HandshakeFixture = .{ .static = static, .psk = psk, .gpa = gpa };
    const t = try std.Thread.spawn(.{}, HandshakeFixture.serve, .{ &fx, server.stream, &server_link });

    const res = try clientHandshake(gpa, client.stream, static.public_key, psk, "hello=1\n");
    t.join();
    defer res.link.destroy();
    defer if (server_link) |l| l.destroy();
    try std.testing.expect(server_link != null);

    // Build a payload at the IPv4 UDP max: proto.max_payload = 65507.
    const big = try gpa.alloc(u8, proto.max_payload);
    defer gpa.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i);
    try res.link.send(.data, 0xdeadbeef, big);
    const frame = try server_link.?.recvFrame();
    try std.testing.expectEqual(proto.FrameType.data, frame.type);
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), frame.id);
    try std.testing.expectEqualSlices(u8, big, frame.payload);
}

test "ZNL6 handshake round trip and record padding" {
    const gpa = std.testing.allocator;
    const static = noise.KeyPair.generate();
    const psk = noise.pskFromSecret("hunter2");
    const client, const server = try loopbackPair(gpa);
    var server_link: ?*Link = null;
    var fx: HandshakeFixture = .{ .static = static, .psk = psk, .gpa = gpa };
    const t = try std.Thread.spawn(.{}, HandshakeFixture.serve, .{ &fx, server.stream, &server_link });

    const res = try clientHandshake(gpa, client.stream, static.public_key, psk, "hello=1\n");
    t.join();
    defer res.link.destroy();
    defer if (server_link) |l| l.destroy();
    try std.testing.expect(server_link != null);

    // Send one frame and verify the on-wire record is at least record_bucket.
    try res.link.send(.ping, 7, "pingpl");
    const frame = try server_link.?.recvFrame();
    try std.testing.expectEqual(proto.FrameType.ping, frame.type);
    try std.testing.expectEqual(@as(u32, 7), frame.id);
    try std.testing.expectEqualStrings("pingpl", frame.payload);
    // bytes_rx counts the 2-byte length + the padded ciphertext; must be ≥ record_bucket.
    try std.testing.expect(server_link.?.bytes_rx.load(.monotonic) >= 2 + record_bucket);
}

fn expectHandshakeRejection(client: PairSide, want: anytype, server: *std.Thread, server_link: *?*Link) !void {
    const res = want;
    server.join();
    if (res) |ok| {
        ok.link.destroy();
        return error.HandshakeUnexpectedlySucceeded;
    } else |err| {
        // The server closes the connection on AuthenticationFailed; the client
        // can see any of these, depending on timing.
        try std.testing.expect(err == error.EndOfStream or err == error.AuthenticationFailed or err == error.ConnectionReset);
        client.stream.close();
    }
    try std.testing.expect(server_link.* == null);
}

test "ZNL6 handshake rejects a wrong proxy public key" {
    const gpa = std.testing.allocator;
    const static = noise.KeyPair.generate();
    const other = noise.KeyPair.generate();
    const psk = noise.pskFromSecret("s");
    const client, const server = try loopbackPair(gpa);
    var server_link: ?*Link = null;
    var fx: HandshakeFixture = .{ .static = static, .psk = psk, .gpa = gpa };
    var t = try std.Thread.spawn(.{}, HandshakeFixture.serve, .{ &fx, server.stream, &server_link });
    try expectHandshakeRejection(client, clientHandshake(gpa, client.stream, other.public_key, psk, "hello=1\n"), &t, &server_link);
}

test "ZNL6 handshake rejects a wrong secret" {
    const gpa = std.testing.allocator;
    const static = noise.KeyPair.generate();
    const client, const server = try loopbackPair(gpa);
    var server_link: ?*Link = null;
    var fx: HandshakeFixture = .{ .static = static, .psk = noise.pskFromSecret("right"), .gpa = gpa };
    var t = try std.Thread.spawn(.{}, HandshakeFixture.serve, .{ &fx, server.stream, &server_link });
    try expectHandshakeRejection(client, clientHandshake(gpa, client.stream, static.public_key, noise.pskFromSecret("wrong"), "hello=1\n"), &t, &server_link);
}
