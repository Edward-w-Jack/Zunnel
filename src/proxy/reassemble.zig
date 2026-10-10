//! IPv4 fragment reassembly for packets coming out of the TUN. One instance
//! per `Tunnel`; the TUN reader thread holds `netstack.lock` while calling
//! into us. The table merges fragments into complete IP packets and times
//! out partial reassemblies after 30 s.
//!
//! Memory is bounded: at most `max_concurrent` reassemblies at once, each at
//! most `max_packet` bytes. Fragments beyond those bounds are dropped.
const std = @import("std");
const packet = @import("packet.zig");

const Allocator = std.mem.Allocator;
const log = std.log.scoped(.reassemble);

/// IPv4 datagrams can grow to 65535 bytes total.
pub const max_packet = 65535;
/// How long we hold onto an incomplete reassembly before dropping it.
pub const timeout_ms: i64 = 30_000;

const max_concurrent = 64;
const max_intervals = 32;

/// A contiguous range of received payload bytes.
const Interval = struct { from: u16, to: u16 };

const Key = struct {
    src: [4]u8,
    dst: [4]u8,
    proto: u8,
    ip_id: u16,
};

/// A single in-flight reassembly.
const Entry = struct {
    key: Key,
    /// Full reassembled packet buffer (IP header + payload). We know the
    /// header size from the offset=0 fragment; until then this is undefined
    /// below `header_len`.
    buf: []u8,
    /// IP header length (ihl*4), filled when the offset=0 fragment arrives.
    header_len: u16 = 0,
    /// Have we seen the offset=0 fragment?
    have_head: bool = false,
    /// Final total payload length, set when MF=0 is received.
    final_payload_len: ?u32 = null,
    /// Contiguous payload byte ranges we have received.
    intervals: std.ArrayList(Interval) = .empty,
    /// `clock.monotonicMs` of the first fragment, for timeout sweep.
    arrived: i64,
};

pub const Table = struct {
    gpa: Allocator,
    entries: std.ArrayList(*Entry) = .empty,
    /// Owns the slice of bytes returned by `offer`; cleared on the next
    /// `offer` or `sweep` call.
    pending_free: ?*Entry = null,

    pub fn init(gpa: Allocator) Table {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Table) void {
        if (self.pending_free) |e| self.destroyEntry(e);
        for (self.entries.items) |e| self.destroyEntry(e);
        self.entries.deinit(self.gpa);
    }

    fn destroyEntry(self: *Table, e: *Entry) void {
        self.gpa.free(e.buf);
        e.intervals.deinit(self.gpa);
        self.gpa.destroy(e);
    }

    /// Feed one IPv4 packet. If `pkt` is a complete, non-fragmented packet
    /// `offer` passes it straight through; if `pkt` is a fragment, it is
    /// buffered. When the last fragment of a datagram arrives, the full
    /// packet is returned. The slice is owned by the Table until the next
    /// `offer` or `sweep` call.
    pub fn offer(self: *Table, pkt: []const u8, now: i64) ?[]const u8 {
        self.releasePending();

        const hdr = packet.parseIp4Header(pkt) orelse return null;
        if (!packet.ip4IsFragment(hdr)) return pkt;

        const key: Key = .{ .src = hdr.src, .dst = hdr.dst, .proto = hdr.proto, .ip_id = hdr.ip_id };
        // Even with the minimal 20-byte header, a datagram's payload ends by
        // 65515. A fragment reaching past that can never complete a valid
        // packet, so the whole reassembly goes.
        const end = @as(u32, hdr.frag_offset) + @as(u32, @intCast(hdr.payload.len));
        if (end > max_packet - 20) {
            if (self.find(key)) |e| self.drop(e);
            return null;
        }

        const entry = self.find(key) orelse self.create(key, now) orelse return null;

        if (hdr.frag_offset == 0 and !entry.have_head) {
            // Head fragment: capture the IP header. Reset total_length,
            // flags/offset and checksum later when the packet is complete.
            if (hdr.header.len > max_packet) {
                self.drop(entry);
                return null;
            }
            @memcpy(entry.buf[0..hdr.header.len], hdr.header);
            entry.header_len = @intCast(hdr.header.len);
            entry.have_head = true;
        }

        if (!entry.have_head) {
            // Non-head arrived first: we don't know the header slot yet. Hold
            // the payload bytes at a provisional [max_header=60] offset. This
            // way the later head fragment can memcpy its header into [0..60]
            // without stepping on payload. In practice headers are 20 bytes
            // and this provisional offset is a drop-in. We trade 40 bytes of
            // slop for simplicity.
            // Equivalent to: payload bytes always sit at buf[60 + offset..];
            // on completion we copy them left by (60 - header_len).
        }

        const slot_offset: u32 = 60 + @as(u32, hdr.frag_offset);
        if (slot_offset + hdr.payload.len > entry.buf.len) {
            self.drop(entry);
            return null;
        }
        @memcpy(entry.buf[slot_offset..][0..hdr.payload.len], hdr.payload);

        // Track the interval in [hdr.frag_offset, hdr.frag_offset + len).
        if (!self.addInterval(entry, .{ .from = hdr.frag_offset, .to = @intCast(end) })) {
            self.drop(entry);
            return null;
        }
        if (!hdr.more_fragments) entry.final_payload_len = end;

        return self.completeIfReady(entry);
    }

    /// Clear reassemblies that haven't made progress in `timeout_ms`.
    pub fn sweep(self: *Table, now: i64) void {
        self.releasePending();
        var i: usize = 0;
        while (i < self.entries.items.len) {
            const e = self.entries.items[i];
            if (now - e.arrived > timeout_ms) {
                _ = self.entries.swapRemove(i);
                self.destroyEntry(e);
            } else i += 1;
        }
    }

    fn releasePending(self: *Table) void {
        if (self.pending_free) |e| {
            self.destroyEntry(e);
            self.pending_free = null;
        }
    }

    fn find(self: *Table, key: Key) ?*Entry {
        for (self.entries.items) |e| if (std.meta.eql(e.key, key)) return e;
        return null;
    }

    fn create(self: *Table, key: Key, now: i64) ?*Entry {
        if (self.entries.items.len >= max_concurrent) return null;
        const e = self.gpa.create(Entry) catch return null;
        errdefer self.gpa.destroy(e);
        e.* = .{
            .key = key,
            // 60 bytes of header slop + max_packet payload (max 65515 after
            // standard 20-byte header). Allocating max_packet + 60 is 64 KiB
            // and simplifies the "non-head arrives first" case.
            .buf = self.gpa.alloc(u8, max_packet + 60) catch {
                self.gpa.destroy(e);
                return null;
            },
            .arrived = now,
        };
        self.entries.append(self.gpa, e) catch {
            self.gpa.free(e.buf);
            self.gpa.destroy(e);
            return null;
        };
        return e;
    }

    fn drop(self: *Table, e: *Entry) void {
        for (self.entries.items, 0..) |x, i| if (x == e) {
            _ = self.entries.swapRemove(i);
            break;
        };
        self.destroyEntry(e);
    }

    /// Inserts `iv` into `e.intervals`, merging adjacent/overlapping ranges.
    /// Returns false if the interval list is at its cap and the new range
    /// doesn't merge with anything.
    fn addInterval(self: *Table, e: *Entry, iv: Interval) bool {
        var merged: Interval = iv;
        var i: usize = 0;
        while (i < e.intervals.items.len) {
            const cur = e.intervals.items[i];
            if (cur.to < merged.from or cur.from > merged.to) {
                i += 1;
                continue;
            }
            merged.from = @min(merged.from, cur.from);
            merged.to = @max(merged.to, cur.to);
            _ = e.intervals.swapRemove(i);
        }
        if (e.intervals.items.len >= max_intervals) return false;
        e.intervals.append(self.gpa, merged) catch return false;
        return true;
    }

    fn completeIfReady(self: *Table, e: *Entry) ?[]const u8 {
        const total_payload = e.final_payload_len orelse return null;
        if (!e.have_head) return null;
        // Check that one of our intervals covers [0, total_payload).
        var covers = false;
        for (e.intervals.items) |iv| if (iv.from == 0 and iv.to >= total_payload) {
            covers = true;
            break;
        };
        if (!covers) return null;

        // With IP options the header is longer than 20 bytes: check the
        // real total against the 16-bit length field.
        const header_len = e.header_len;
        const total_len: u32 = @as(u32, header_len) + total_payload;
        if (total_len > max_packet) {
            self.drop(e);
            return null;
        }

        // Collapse the 60-byte header slot into the real header length,
        // producing a contiguous [header | payload] in buf[0..total_len].
        if (header_len != 60) {
            std.mem.copyForwards(u8, e.buf[header_len .. header_len + total_payload], e.buf[60 .. 60 + total_payload]);
        }

        // Rewrite the IP header's total-length, flags/offset and checksum.
        std.mem.writeInt(u16, e.buf[2..4], @intCast(total_len), .big);
        std.mem.writeInt(u16, e.buf[6..8], 0, .big); // no fragment flags/offset
        std.mem.writeInt(u16, e.buf[10..12], 0, .big);
        std.mem.writeInt(u16, e.buf[10..12], ipHeaderChecksum(e.buf[0..header_len]), .big);

        // Pop the entry from the active list; keep it live until the next
        // call so the returned slice stays valid.
        for (self.entries.items, 0..) |x, i| if (x == e) {
            _ = self.entries.swapRemove(i);
            break;
        };
        self.pending_free = e;
        return e.buf[0..total_len];
    }

    pub fn count(self: *Table) usize {
        return self.entries.items.len;
    }
};

/// RFC 791 header checksum: one's-complement of the one's-complement sum of
/// the 16-bit words of the IP header (with the checksum field itself zero).
fn ipHeaderChecksum(hdr: []const u8) u16 {
    var s: u32 = 0;
    var i: usize = 0;
    while (i + 1 < hdr.len) : (i += 2) s += std.mem.readInt(u16, hdr[i..][0..2], .big);
    if (hdr.len & 1 == 1) s += @as(u32, hdr[hdr.len - 1]) << 8;
    while (s >> 16 != 0) s = (s & 0xffff) + (s >> 16);
    return ~@as(u16, @truncate(s));
}

// --------------------------------------------------------------------- tests

fn makeFragment(buf: []u8, src: [4]u8, dst: [4]u8, proto: u8, ip_id: u16, frag_offset_bytes: u16, more: bool, payload: []const u8) []u8 {
    std.debug.assert(frag_offset_bytes % 8 == 0);
    const total: u16 = @intCast(20 + payload.len);
    buf[0] = 0x45; // version 4, IHL 5
    buf[1] = 0;
    std.mem.writeInt(u16, buf[2..4], total, .big);
    std.mem.writeInt(u16, buf[4..6], ip_id, .big);
    const mf_bit: u16 = if (more) 0x2000 else 0;
    std.mem.writeInt(u16, buf[6..8], mf_bit | (frag_offset_bytes / 8), .big);
    buf[8] = 64; // TTL
    buf[9] = proto;
    std.mem.writeInt(u16, buf[10..12], 0, .big);
    buf[12..16].* = src;
    buf[16..20].* = dst;
    std.mem.writeInt(u16, buf[10..12], ipHeaderChecksum(buf[0..20]), .big);
    @memcpy(buf[20..][0..payload.len], payload);
    return buf[0..total];
}

test "two-fragment reassembly in order" {
    const gpa = std.testing.allocator;
    var t: Table = .init(gpa);
    defer t.deinit();

    const payload = "0123456789abcdef0123456789abcdef";
    var buf1: [60]u8 = undefined;
    var buf2: [60]u8 = undefined;
    const f1 = makeFragment(&buf1, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, packet.proto_udp, 42, 0, true, payload[0..16]);
    const f2 = makeFragment(&buf2, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, packet.proto_udp, 42, 16, false, payload[16..]);

    try std.testing.expect(t.offer(f1, 1_000) == null);
    const result = t.offer(f2, 1_010).?;
    const parsed = packet.parseIp4(result).?;
    try std.testing.expectEqualSlices(u8, payload, parsed.payload);
}

test "fragments arriving in reverse order" {
    const gpa = std.testing.allocator;
    var t: Table = .init(gpa);
    defer t.deinit();

    const payload = "0123456789abcdef0123456789abcdef";
    var buf1: [60]u8 = undefined;
    var buf2: [60]u8 = undefined;
    const f1 = makeFragment(&buf1, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, packet.proto_udp, 7, 0, true, payload[0..16]);
    const f2 = makeFragment(&buf2, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, packet.proto_udp, 7, 16, false, payload[16..]);

    try std.testing.expect(t.offer(f2, 1_000) == null);
    const result = t.offer(f1, 1_010).?;
    const parsed = packet.parseIp4(result).?;
    try std.testing.expectEqualSlices(u8, payload, parsed.payload);
}

test "a 50 KiB datagram split into MTU-sized fragments reassembles" {
    const gpa = std.testing.allocator;
    var t: Table = .init(gpa);
    defer t.deinit();

    const payload_len: u16 = 50_000;
    const payload = try gpa.alloc(u8, payload_len);
    defer gpa.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i);

    const mtu_payload: u16 = 1480; // 1500 MTU - 20 IP header, aligned to 8
    var off: u16 = 0;
    while (off < payload_len) : (off += mtu_payload) {
        const take = @min(mtu_payload, payload_len - off);
        const more = off + take < payload_len;
        var buf: [1500]u8 = undefined;
        const f = makeFragment(&buf, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, packet.proto_udp, 99, off, more, payload[off..][0..take]);
        if (t.offer(f, 1_000)) |done| {
            try std.testing.expect(!more);
            const parsed = packet.parseIp4(done).?;
            try std.testing.expectEqualSlices(u8, payload, parsed.payload);
            return;
        }
    }
    return error.NeverCompleted;
}

test "complete packets pass straight through" {
    const gpa = std.testing.allocator;
    var t: Table = .init(gpa);
    defer t.deinit();
    var buf: [60]u8 = undefined;
    const pkt = makeFragment(&buf, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, packet.proto_udp, 1, 0, false, "hi");
    const out = t.offer(pkt, 1_000).?;
    try std.testing.expectEqualSlices(u8, pkt, out);
    try std.testing.expectEqual(@as(usize, 0), t.count());
}

test "stale reassemblies are dropped by sweep" {
    const gpa = std.testing.allocator;
    var t: Table = .init(gpa);
    defer t.deinit();
    var buf: [60]u8 = undefined;
    const f1 = makeFragment(&buf, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, packet.proto_udp, 5, 0, true, "head");
    try std.testing.expect(t.offer(f1, 1_000) == null);
    try std.testing.expectEqual(@as(usize, 1), t.count());
    t.sweep(1_000 + timeout_ms - 1);
    try std.testing.expectEqual(@as(usize, 1), t.count());
    t.sweep(1_000 + timeout_ms + 1);
    try std.testing.expectEqual(@as(usize, 0), t.count());
}

test "overflow is rejected" {
    const gpa = std.testing.allocator;
    var t: Table = .init(gpa);
    defer t.deinit();
    var buf: [40]u8 = undefined;
    // offset near max; payload would push total past 65535.
    const f = makeFragment(&buf, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, packet.proto_udp, 1, 65528, false, "overflow");
    try std.testing.expect(t.offer(f, 1_000) == null);
    try std.testing.expectEqual(@as(usize, 0), t.count());
}

test "fragments reaching past the IPv4 maximum are dropped, not reassembled" {
    const gpa = std.testing.allocator;
    var t: Table = .init(gpa);
    defer t.deinit();
    // Fragments covering payload bytes 0..65535: with the 20-byte header
    // that would be a 65555-byte packet, which doesn't fit the u16 length.
    var payload: [1480]u8 = undefined;
    @memset(&payload, 0xab);
    var buf: [1500]u8 = undefined;
    var off: u32 = 0;
    while (off < 65535) {
        const take: u32 = @min(payload.len, 65535 - off);
        const more = off + take < 65535;
        const f = makeFragment(&buf, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, packet.proto_icmp, 3, @intCast(off), more, payload[0..take]);
        try std.testing.expect(t.offer(f, 1_000) == null);
        off += take;
    }
    try std.testing.expectEqual(@as(usize, 0), t.count());
}

test "concurrent cap rejects the 65th reassembly" {
    const gpa = std.testing.allocator;
    var t: Table = .init(gpa);
    defer t.deinit();
    var buf: [40]u8 = undefined;
    var i: u16 = 0;
    while (i < max_concurrent) : (i += 1) {
        const f = makeFragment(&buf, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, packet.proto_udp, i, 0, true, "x");
        try std.testing.expect(t.offer(f, 1_000) == null);
    }
    try std.testing.expectEqual(@as(usize, max_concurrent), t.count());
    const f = makeFragment(&buf, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, packet.proto_udp, 9999, 0, true, "y");
    try std.testing.expect(t.offer(f, 1_000) == null);
    try std.testing.expectEqual(@as(usize, max_concurrent), t.count());
}
