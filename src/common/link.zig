//! The encrypted, framed connection between proxy and agent.
//!
//! Handshake on a fresh TCP connection:
//!   proxy -> agent : "ZNL1" | proxy static public key (32)
//!   agent -> proxy : u16be len | Noise message 1 (payload: agent hello)
//!   proxy -> agent : u16be len | Noise message 2
//!
//! Afterwards each record is `u16be len | ciphertext` and decrypts to one or
//! more whole frames (see proto.zig). Sending never blocks the caller: frames
//! are queued and a dedicated writer thread encrypts and writes them.
const std = @import("std");
const noise = @import("noise.zig");
const proto = @import("proto.zig");
const sock = @import("sock.zig");

const Allocator = std.mem.Allocator;
const log = std.log.scoped(.link);

const max_record_plain = 60 * 1024;
const max_record = max_record_plain + noise.tag_len;
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
    handle: sock.Handle,
    tx: noise.CipherState,
    rx: noise.CipherState,

    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    queue: std.ArrayList(u8) = .empty,
    closed: bool = false,
    writer: ?std.Thread = null,
    /// When the last record arrived (ms); the writer closes the link when it goes stale.
    last_rx: std.atomic.Value(i64) = .init(0),

    rx_buf: [max_record]u8 = undefined,
    rx_pos: usize = 0,
    rx_len: usize = 0,

    fn create(gpa: Allocator, handle: sock.Handle, t: noise.Transport) !*Link {
        const self = try gpa.create(Link);
        self.* = .{ .gpa = gpa, .handle = handle, .tx = t.send, .rx = t.recv };
        self.last_rx.store(std.time.milliTimestamp(), .monotonic);
        errdefer gpa.destroy(self);
        // A peer that stops reading for this long is as dead as a silent one.
        sock.setSendTimeout(handle, proto.link_dead_after_ms);
        self.writer = try std.Thread.spawn(.{}, writerLoop, .{self});
        return self;
    }

    /// Closes the link (if needed), waits for the writer and frees everything.
    /// No other thread may be using the link anymore.
    pub fn destroy(self: *Link) void {
        self.close();
        if (self.writer) |t| t.join();
        self.queue.deinit(self.gpa);
        sock.close(self.handle);
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
        sock.shutdown(self.handle, .both);
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

        var last_ping = std.time.milliTimestamp();
        while (true) {
            {
                self.mutex.lock();
                defer self.mutex.unlock();
                while (true) {
                    if (self.closed) return;
                    // Heartbeat: both ends ping; whatever arrives refreshes last_rx.
                    const now = std.time.milliTimestamp();
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

            // Pack whole frames into records of at most max_record_plain bytes.
            var off: usize = 0;
            while (off < batch.items.len) {
                var end = off;
                while (end < batch.items.len) {
                    const h = proto.parseHeader(batch.items[end..][0..proto.header_len]);
                    const flen = proto.header_len + @as(usize, h.len);
                    if (end > off and end + flen - off > max_record_plain) break;
                    end += flen;
                }
                const plain = batch.items[off..end];
                const ct_len = plain.len + noise.tag_len;
                std.mem.writeInt(u16, out[0..2], @intCast(ct_len), .big);
                self.tx.encrypt(out[2..][0..ct_len], "", plain) catch {
                    self.close();
                    return;
                };
                sock.sendAll(self.handle, out[0 .. 2 + ct_len]) catch {
                    self.close();
                    return;
                };
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
        try sock.recvExact(self.handle, &lb);
        const len = std.mem.readInt(u16, &lb, .big);
        if (len <= noise.tag_len or len > max_record) return error.InvalidMessage;
        try sock.recvExact(self.handle, self.rx_buf[0..len]);
        const plain_len = len - noise.tag_len;
        try self.rx.decrypt(self.rx_buf[0..plain_len], "", self.rx_buf[0..len]);
        self.rx_pos = 0;
        self.rx_len = plain_len;
        self.last_rx.store(std.time.milliTimestamp(), .monotonic);
    }
};

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

fn sendMsg(h: sock.Handle, msg: []const u8) !void {
    var lb: [2]u8 = undefined;
    std.mem.writeInt(u16, &lb, @intCast(msg.len), .big);
    try sock.sendAll(h, &lb);
    try sock.sendAll(h, msg);
}

fn recvMsg(h: sock.Handle, buf: []u8) ![]u8 {
    var lb: [2]u8 = undefined;
    try sock.recvExact(h, &lb);
    const len = std.mem.readInt(u16, &lb, .big);
    if (len > buf.len) return error.InvalidMessage;
    try sock.recvExact(h, buf[0..len]);
    return buf[0..len];
}

pub const ClientResult = struct {
    link: *Link,
    server_key: [noise.key_len]u8,
};

/// Agent side. `expected_key` == null accepts any proxy key (caller should show
/// the fingerprint). On success the link owns `handle`.
pub fn clientHandshake(
    gpa: Allocator,
    handle: sock.Handle,
    expected_key: ?[noise.key_len]u8,
    psk: [noise.key_len]u8,
    hello: []const u8,
) !ClientResult {
    sock.setRecvTimeout(handle, handshake_timeout_ms);
    var pre: [proto.magic.len + noise.key_len]u8 = undefined;
    try sock.recvExact(handle, &pre);
    if (!std.mem.eql(u8, pre[0..proto.magic.len], proto.magic)) {
        std.log.err("expected protocol {s}, proxy sent {any}", .{ proto.magic, pre[0..proto.magic.len] });
        return error.ProtocolMismatch;
    }
    const server_key = pre[proto.magic.len..].*;
    if (expected_key) |k| {
        if (!std.mem.eql(u8, &k, &server_key)) return error.KeyMismatch;
    }

    var hs = noise.Initiator.init(server_key, psk, proto.magic);
    var buf: [max_hello + 64]u8 = undefined;
    try sendMsg(handle, try hs.writeMessage1(&buf, hello[0..@min(hello.len, max_hello)]));

    var payload: [64]u8 = undefined;
    const msg2 = try recvMsg(handle, &buf);
    const transport, _ = try hs.readMessage2(msg2, &payload);
    sock.setRecvTimeout(handle, 0);
    sock.setKeepAlive(handle);
    sock.setNoDelay(handle);
    return .{ .link = try Link.create(gpa, handle, transport), .server_key = server_key };
}

pub const ServerResult = struct {
    link: *Link,
    hello: []u8,
};

/// Proxy side. On success the link owns `handle` and `hello` points into `hello_buf`.
pub fn serverHandshake(
    gpa: Allocator,
    handle: sock.Handle,
    static: noise.KeyPair,
    psk: [noise.key_len]u8,
    hello_buf: *[max_hello]u8,
) !ServerResult {
    sock.setRecvTimeout(handle, handshake_timeout_ms);
    try sock.sendAll(handle, proto.magic ++ static.public_key);

    var hs = noise.Responder.init(static, psk, proto.magic);
    var buf: [max_hello + 64]u8 = undefined;
    const msg1 = try recvMsg(handle, &buf);
    const hello = try hs.readMessage1(msg1, hello_buf);

    var out: [64]u8 = undefined;
    const transport, const msg2 = try hs.writeMessage2(&out, "");
    try sendMsg(handle, msg2);
    sock.setRecvTimeout(handle, 0);
    sock.setKeepAlive(handle);
    sock.setNoDelay(handle);
    return .{ .link = try Link.create(gpa, handle, transport), .hello = hello };
}

pub const max_hello_len = max_hello;
