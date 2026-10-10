//! Minimal IPv4/TCP/UDP parsing and packet construction for traffic that does
//! not go through lwIP (UDP, connection-refused RSTs).
const std = @import("std");

pub const proto_icmp = 1;
pub const proto_tcp = 6;
pub const proto_udp = 17;

pub const tcp_fin = 0x01;
pub const tcp_syn = 0x02;
pub const tcp_rst = 0x04;
pub const tcp_ack = 0x10;

pub const Ip4 = struct {
    src: [4]u8,
    dst: [4]u8,
    proto: u8,
    /// Transport header + payload.
    payload: []const u8,
};

pub fn parseIp4(pkt: []const u8) ?Ip4 {
    if (pkt.len < 20 or pkt[0] >> 4 != 4) return null;
    const ihl = @as(usize, pkt[0] & 0x0f) * 4;
    const total = std.mem.readInt(u16, pkt[2..4], .big);
    if (ihl < 20 or total < ihl or total > pkt.len) return null;
    // Fragments are not supported (MF set or non-zero offset).
    const frag = std.mem.readInt(u16, pkt[6..8], .big);
    if (frag & 0x3fff != 0) return null;
    return .{
        .src = pkt[12..16].*,
        .dst = pkt[16..20].*,
        .proto = pkt[9],
        .payload = pkt[ihl..total],
    };
}

/// Header slice of an IPv4 packet, with fragment info -- for the reassembly
/// path, which parses even fragmented packets.
pub const Ip4Header = struct {
    src: [4]u8,
    dst: [4]u8,
    proto: u8,
    ip_id: u16,
    /// Header bytes (ihl*4). Aliases `pkt`.
    header: []const u8,
    /// Payload bytes (total - ihl*4). Aliases `pkt`.
    payload: []const u8,
    /// Payload offset in the reassembled packet, in bytes. Always a multiple
    /// of 8 unless MF=0.
    frag_offset: u16,
    /// True if more fragments follow this one.
    more_fragments: bool,
};

pub fn parseIp4Header(pkt: []const u8) ?Ip4Header {
    if (pkt.len < 20 or pkt[0] >> 4 != 4) return null;
    const ihl = @as(usize, pkt[0] & 0x0f) * 4;
    const total = std.mem.readInt(u16, pkt[2..4], .big);
    if (ihl < 20 or total < ihl or total > pkt.len) return null;
    const ip_id = std.mem.readInt(u16, pkt[4..6], .big);
    const frag = std.mem.readInt(u16, pkt[6..8], .big);
    const mf = frag & 0x2000 != 0;
    const offset_blocks = frag & 0x1fff;
    return .{
        .src = pkt[12..16].*,
        .dst = pkt[16..20].*,
        .proto = pkt[9],
        .ip_id = ip_id,
        .header = pkt[0..ihl],
        .payload = pkt[ihl..total],
        .frag_offset = @as(u16, offset_blocks) * 8,
        .more_fragments = mf,
    };
}

/// True if the IP packet is a non-head or non-tail fragment of a larger
/// datagram (MF=1 or offset > 0).
pub fn ip4IsFragment(hdr: Ip4Header) bool {
    return hdr.more_fragments or hdr.frag_offset != 0;
}

pub const Tcp = struct {
    sport: u16,
    dport: u16,
    seq: u32,
    flags: u8,
};

pub fn parseTcp(seg: []const u8) ?Tcp {
    if (seg.len < 20) return null;
    return .{
        .sport = std.mem.readInt(u16, seg[0..2], .big),
        .dport = std.mem.readInt(u16, seg[2..4], .big),
        .seq = std.mem.readInt(u32, seg[4..8], .big),
        .flags = seg[13],
    };
}

pub const Udp = struct {
    sport: u16,
    dport: u16,
    data: []const u8,
};

pub fn parseUdp(dgram: []const u8) ?Udp {
    if (dgram.len < 8) return null;
    const len = std.mem.readInt(u16, dgram[4..6], .big);
    if (len < 8 or len > dgram.len) return null;
    return .{
        .sport = std.mem.readInt(u16, dgram[0..2], .big),
        .dport = std.mem.readInt(u16, dgram[2..4], .big),
        .data = dgram[8..len],
    };
}

fn sum16(data: []const u8, initial: u32) u32 {
    var s = initial;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) s += std.mem.readInt(u16, data[i..][0..2], .big);
    if (data.len & 1 == 1) s += @as(u32, data[data.len - 1]) << 8;
    return s;
}

fn fold(s0: u32) u16 {
    var s = s0;
    while (s >> 16 != 0) s = (s & 0xffff) + (s >> 16);
    return ~@as(u16, @truncate(s));
}

fn pseudoSum(src: [4]u8, dst: [4]u8, proto: u8, len: usize) u32 {
    var s = sum16(&src, 0);
    s = sum16(&dst, s);
    return s + proto + @as(u32, @intCast(len));
}

fn writeIp4Header(buf: []u8, src: [4]u8, dst: [4]u8, proto: u8, total: usize) void {
    buf[0] = 0x45;
    buf[1] = 0;
    std.mem.writeInt(u16, buf[2..4], @intCast(total), .big);
    std.mem.writeInt(u16, buf[4..6], 0, .big); // id
    std.mem.writeInt(u16, buf[6..8], 0x4000, .big); // DF
    buf[8] = 64; // TTL
    buf[9] = proto;
    std.mem.writeInt(u16, buf[10..12], 0, .big);
    buf[12..16].* = src;
    buf[16..20].* = dst;
    std.mem.writeInt(u16, buf[10..12], fold(sum16(buf[0..20], 0)), .big);
}

/// Builds an IPv4/UDP packet into `buf`. Returns null if it does not fit.
pub fn buildUdp4(buf: []u8, src: [4]u8, sport: u16, dst: [4]u8, dport: u16, data: []const u8) ?[]u8 {
    const total = 20 + 8 + data.len;
    if (total > buf.len or total > 0xffff) return null;
    const udp = buf[20..total];
    std.mem.writeInt(u16, udp[0..2], sport, .big);
    std.mem.writeInt(u16, udp[2..4], dport, .big);
    std.mem.writeInt(u16, udp[4..6], @intCast(udp.len), .big);
    std.mem.writeInt(u16, udp[6..8], 0, .big);
    @memcpy(udp[8..], data);
    var ck = fold(sum16(udp, pseudoSum(src, dst, proto_udp, udp.len)));
    if (ck == 0) ck = 0xffff;
    std.mem.writeInt(u16, udp[6..8], ck, .big);
    writeIp4Header(buf, src, dst, proto_udp, total);
    return buf[0..total];
}

pub const icmp_echo_reply = 0;
pub const icmp_echo_request = 8;

/// Turns an ICMP echo request into the matching echo reply (into `buf`).
pub fn buildIcmpEchoReply4(buf: []u8, req: Ip4) ?[]u8 {
    const icmp_len = req.payload.len;
    const total = 20 + icmp_len;
    if (icmp_len < 8 or total > buf.len) return null;
    const icmp = buf[20..total];
    @memcpy(icmp, req.payload);
    icmp[0] = icmp_echo_reply;
    icmp[1] = 0;
    std.mem.writeInt(u16, icmp[2..4], 0, .big);
    std.mem.writeInt(u16, icmp[2..4], fold(sum16(icmp, 0)), .big);
    writeIp4Header(buf, req.dst, req.src, proto_icmp, total);
    return buf[0..total];
}

pub const icmp_dest_unreachable = 3;
pub const unreach_net = 0;
pub const unreach_host = 1;
pub const unreach_port = 3;
pub const unreach_admin_prohibited = 13;

/// Builds an ICMP destination-unreachable for `original` (an IPv4 packet we
/// are refusing), sent back to its source as if from its destination. The
/// message quotes the original IP header plus 8 bytes, as RFC 792 requires.
pub fn buildIcmpUnreachable4(buf: []u8, code: u8, original: []const u8) ?[]u8 {
    const ip = parseIp4(original) orelse return null;
    const ihl = @as(usize, original[0] & 0x0f) * 4;
    const quote_len = @min(original.len, ihl + 8);
    const total = 20 + 8 + quote_len;
    if (total > buf.len) return null;
    const icmp = buf[20..total];
    icmp[0] = icmp_dest_unreachable;
    icmp[1] = code;
    @memset(icmp[2..8], 0);
    @memcpy(icmp[8..], original[0..quote_len]);
    std.mem.writeInt(u16, icmp[2..4], fold(sum16(icmp, 0)), .big);
    writeIp4Header(buf, ip.dst, ip.src, proto_icmp, total);
    return buf[0..total];
}

/// Builds a RST|ACK answering a SYN with sequence number `syn_seq`.
pub fn buildRst4(buf: *[40]u8, src: [4]u8, sport: u16, dst: [4]u8, dport: u16, syn_seq: u32) []u8 {
    const tcp = buf[20..40];
    @memset(tcp, 0);
    std.mem.writeInt(u16, tcp[0..2], sport, .big);
    std.mem.writeInt(u16, tcp[2..4], dport, .big);
    std.mem.writeInt(u32, tcp[4..8], 0, .big);
    std.mem.writeInt(u32, tcp[8..12], syn_seq +% 1, .big);
    tcp[12] = 5 << 4;
    tcp[13] = tcp_rst | tcp_ack;
    std.mem.writeInt(u16, tcp[16..18], fold(sum16(tcp, pseudoSum(src, dst, proto_tcp, tcp.len))), .big);
    writeIp4Header(buf, src, dst, proto_tcp, 40);
    return buf;
}

test "icmp echo reply" {
    // Echo request 10.0.0.2 -> 10.0.0.1, id 0x1234 seq 1, payload "abc".
    var req_buf: [64]u8 = undefined;
    const icmp_req = [_]u8{ 8, 0, 0, 0, 0x12, 0x34, 0, 1, 'a', 'b', 'c' };
    @memcpy(req_buf[20..][0..icmp_req.len], &icmp_req);
    writeIp4Header(&req_buf, .{ 10, 0, 0, 2 }, .{ 10, 0, 0, 1 }, proto_icmp, 20 + icmp_req.len);
    const req = parseIp4(req_buf[0 .. 20 + icmp_req.len]).?;

    var out: [64]u8 = undefined;
    const reply = buildIcmpEchoReply4(&out, req).?;
    const ip = parseIp4(reply).?;
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &ip.src);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 2 }, &ip.dst);
    try std.testing.expectEqual(@as(u8, icmp_echo_reply), ip.payload[0]);
    try std.testing.expectEqualSlices(u8, icmp_req[4..], ip.payload[4..]);
    try std.testing.expectEqual(@as(u16, 0), fold(sum16(ip.payload, 0)));
    try std.testing.expectEqual(@as(u16, 0), fold(sum16(reply[0..20], 0)));
}

test "icmp unreachable quotes the original header" {
    var orig_buf: [64]u8 = undefined;
    const orig = buildUdp4(&orig_buf, .{ 10, 0, 0, 2 }, 40000, .{ 10, 0, 0, 9 }, 161, "probe").?;
    var out: [128]u8 = undefined;
    const msg = buildIcmpUnreachable4(&out, unreach_port, orig).?;
    const ip = parseIp4(msg).?;
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 9 }, &ip.src);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 2 }, &ip.dst);
    try std.testing.expectEqual(@as(u8, proto_icmp), ip.proto);
    try std.testing.expectEqual(@as(u8, icmp_dest_unreachable), ip.payload[0]);
    try std.testing.expectEqual(@as(u8, unreach_port), ip.payload[1]);
    try std.testing.expectEqual(@as(u16, 0), fold(sum16(ip.payload, 0)));
    // Quoted: original 20-byte IP header + the 8-byte UDP header.
    try std.testing.expectEqual(@as(usize, 8 + 28), ip.payload.len);
    const quoted = parseUdp(ip.payload[8 + 20 ..]);
    try std.testing.expect(quoted == null); // only 8 bytes quoted: header but no full datagram
    try std.testing.expectEqual(@as(u16, 161), std.mem.readInt(u16, ip.payload[8 + 20 + 2 ..][0..2], .big));
}

test "udp round trip and checksums" {
    var buf: [128]u8 = undefined;
    const pkt = buildUdp4(&buf, .{ 10, 0, 0, 1 }, 53, .{ 10, 0, 0, 2 }, 40000, "hi").?;
    // A packet containing a valid checksum sums to zero.
    try std.testing.expectEqual(@as(u16, 0), fold(sum16(pkt[0..20], 0)));
    try std.testing.expectEqual(@as(u16, 0), fold(sum16(pkt[20..], pseudoSum(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, proto_udp, pkt.len - 20))));
    const ip = parseIp4(pkt).?;
    const udp = parseUdp(ip.payload).?;
    try std.testing.expectEqual(@as(u16, 53), udp.sport);
    try std.testing.expectEqualStrings("hi", udp.data);
}

test "fuzz packet parsing and replies" {
    try std.testing.fuzz({}, struct {
        fn one(_: void, input: []const u8) anyerror!void {
            // Packets come straight from the TUN: parsing must never read out
            // of bounds, and replies built from them must be well-formed.
            const ip = parseIp4(input) orelse return;
            try std.testing.expect(ip.payload.len <= input.len);
            var out: [65536 + 64]u8 = undefined;
            switch (ip.proto) {
                proto_tcp => _ = parseTcp(ip.payload),
                proto_udp => if (parseUdp(ip.payload)) |u| try std.testing.expect(u.data.len <= ip.payload.len),
                proto_icmp => if (buildIcmpEchoReply4(&out, ip)) |reply| {
                    try std.testing.expectEqual(@as(u16, 0), fold(sum16(reply[0..20], 0)));
                    try std.testing.expectEqual(@as(u16, 0), fold(sum16(reply[20..], 0)));
                },
                else => {},
            }
            if (buildIcmpUnreachable4(&out, unreach_host, input)) |msg| {
                try std.testing.expect(msg.len <= 20 + 8 + 60 + 8);
                try std.testing.expectEqual(@as(u16, 0), fold(sum16(msg[20..], 0)));
            }
        }
    }.one, .{ .corpus = &.{
        // IPv4/UDP 10.0.0.2:40000 -> 10.0.0.9:161, 5-byte payload
        &.{ 0x45, 0, 0, 33, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 9, 0x9c, 0x40, 0, 161, 0, 13, 0, 0, 'p', 'r', 'o', 'b', 'e' },
        // IPv4/ICMP echo request with 4 payload bytes
        &.{ 0x45, 0, 0, 32, 0, 0, 0x40, 0, 64, 1, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1, 8, 0, 0, 0, 0x12, 0x34, 0, 1, 'p', 'i', 'n', 'g' },
        // IPv4/TCP SYN header only
        &.{ 0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 2, 10, 0, 0, 9, 0x9c, 0x40, 0, 22, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 2, 0xff, 0xff, 0, 0, 0, 0 },
    } });
}
