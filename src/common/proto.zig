//! Wire protocol spoken inside the encrypted link.
//!
//! Every record carries one or more frames:
//!   type: u8 | flags: u8 | id: u32be | len: u16be | payload[len]
//!
//! `id` names a forwarded flow. The proxy allocates ids below `agent_id_bit`
//! (TUN flows, ICMP requests, listener ids); the agent allocates ids with
//! `agent_id_bit` set (connections accepted by its listeners).
const std = @import("std");

/// Bump the digit whenever the handshake or framing changes incompatibly.
pub const magic = "ZNL4";
pub const default_port: u16 = 11601;
/// Both ends send a ping this often...
pub const heartbeat_interval_ms = 10_000;
/// ...and drop the link when nothing has arrived for this long.
pub const link_dead_after_ms = 30_000;
/// Dial timeout used when a connect request does not carry one.
pub const default_dial_timeout_ms: u16 = 3000;
pub const header_len = 8;
pub const max_payload = 16 * 1024;
/// Per-flow, per-direction flow-control window for TCP flows.
pub const initial_window: u32 = 256 * 1024;
/// 240.0.0.0/4 on the proxy side is mapped to the agent's own 127.0.0.1.
pub const magic_localhost_net = [4]u8{ 240, 0, 0, 0 };
pub const agent_id_bit: u32 = 0x8000_0000;

pub const FrameType = enum(u8) {
    ping = 1,
    pong = 2,
    /// proxy -> agent: open a flow (payload: ConnectRequest)
    connect = 3,
    /// agent -> proxy: flow is open
    connect_ok = 4,
    /// agent -> proxy: flow failed (payload: FailReason)
    connect_fail = 5,
    /// bytes (TCP) or one datagram (UDP)
    data = 6,
    /// flow-control credit (payload: u32be bytes)
    window = 7,
    /// sender will send no more data on this flow (TCP half-close)
    fin = 8,
    /// abort the flow in both directions
    reset = 9,
    /// proxy -> agent: ping an address (payload: IcmpEcho)
    icmp_echo = 10,
    /// agent -> proxy: result (payload: ok u8 | rtt_ms u16be)
    icmp_reply = 11,
    /// proxy -> agent: open a listener; id = listener id (payload: Endpoint, bind address)
    listener_add = 12,
    listener_ok = 13,
    /// agent -> proxy (payload: error text)
    listener_fail = 14,
    /// proxy -> agent: close a listener
    listener_del = 15,
    /// agent -> proxy: a listener accepted a connection/association; id = new
    /// flow id (payload: listener id u32be | Endpoint of the peer). The proxy
    /// answers with connect_ok / connect_fail like the agent does for `connect`.
    accepted = 16,
    /// agent -> proxy: the target answered a UDP flow with ICMP unreachable
    /// (payload: ICMP code u8, 3 = port unreachable). The flow stays open.
    icmp_unreachable = 17,
    _,
};

pub const Header = struct {
    type: FrameType,
    id: u32,
    len: u16,
};

pub fn writeHeader(buf: *[header_len]u8, ftype: FrameType, id: u32, len: u16) void {
    buf[0] = @intFromEnum(ftype);
    buf[1] = 0;
    std.mem.writeInt(u32, buf[2..6], id, .big);
    std.mem.writeInt(u16, buf[6..8], len, .big);
}

pub fn parseHeader(buf: *const [header_len]u8) Header {
    return .{
        .type = @enumFromInt(buf[0]),
        .id = std.mem.readInt(u32, buf[2..6], .big),
        .len = std.mem.readInt(u16, buf[6..8], .big),
    };
}

pub const Transport = enum(u8) { tcp = 6, udp = 17, _ };

pub const FailReason = enum(u8) {
    refused = 1,
    unreachable_host = 2,
    timeout = 3,
    other = 4,
    unreachable_net = 5,
    /// Blocked locally (e.g. by a host firewall on the agent).
    prohibited = 6,
    _,

    pub fn fromError(err: anyerror) FailReason {
        return switch (err) {
            error.ConnectionRefused => .refused,
            error.NetworkUnreachable => .unreachable_net,
            error.HostUnreachable, error.AddressNotAvailable => .unreachable_host,
            error.ConnectionTimedOut, error.Timeout => .timeout,
            error.AccessDenied, error.PermissionDenied => .prohibited,
            else => .other,
        };
    }
};

pub const ConnectRequest = struct {
    transport: Transport,
    /// 4 bytes for IPv4, 16 for IPv6.
    addr: []const u8,
    port: u16,
    /// Dial timeout for `connect` (0 = not sent; the agent uses its default).
    timeout_ms: u16 = 0,

    pub const max_len = 4 + 16 + 2;

    pub fn encode(self: ConnectRequest, buf: *[max_len]u8) []u8 {
        std.debug.assert(self.addr.len == 4 or self.addr.len == 16);
        buf[0] = @intFromEnum(self.transport);
        std.mem.writeInt(u16, buf[1..3], self.port, .big);
        buf[3] = @intCast(self.addr.len);
        @memcpy(buf[4..][0..self.addr.len], self.addr);
        const end = 4 + self.addr.len;
        if (self.timeout_ms == 0) return buf[0..end];
        std.mem.writeInt(u16, buf[end..][0..2], self.timeout_ms, .big);
        return buf[0 .. end + 2];
    }

    pub fn decode(payload: []const u8) error{InvalidMessage}!ConnectRequest {
        if (payload.len < 4) return error.InvalidMessage;
        const alen = payload[3];
        if (alen != 4 and alen != 16) return error.InvalidMessage;
        const end = 4 + @as(usize, alen);
        const timeout_ms: u16 = if (payload.len == end)
            0
        else if (payload.len == end + 2)
            std.mem.readInt(u16, payload[end..][0..2], .big)
        else
            return error.InvalidMessage;
        return .{
            .transport = @enumFromInt(payload[0]),
            .port = std.mem.readInt(u16, payload[1..3], .big),
            .addr = payload[4..end],
            .timeout_ms = timeout_ms,
        };
    }
};

/// `connect`, `listener_add` and `accepted` share this address encoding.
pub const Endpoint = ConnectRequest;

pub const IcmpEcho = struct {
    addr: [4]u8,
    timeout_ms: u16,

    pub fn encode(self: IcmpEcho) [6]u8 {
        var b: [6]u8 = undefined;
        b[0..4].* = self.addr;
        std.mem.writeInt(u16, b[4..6], self.timeout_ms, .big);
        return b;
    }

    pub fn decode(p: []const u8) error{InvalidMessage}!IcmpEcho {
        if (p.len != 6) return error.InvalidMessage;
        return .{ .addr = p[0..4].*, .timeout_ms = std.mem.readInt(u16, p[4..6], .big) };
    }
};

pub const Accepted = struct {
    listener_id: u32,
    peer: Endpoint,

    pub const max_len = 4 + Endpoint.max_len;

    pub fn encode(self: Accepted, buf: *[max_len]u8) []u8 {
        std.mem.writeInt(u32, buf[0..4], self.listener_id, .big);
        const rest = self.peer.encode(buf[4..][0..Endpoint.max_len]);
        return buf[0 .. 4 + rest.len];
    }

    pub fn decode(p: []const u8) error{InvalidMessage}!Accepted {
        if (p.len < 4) return error.InvalidMessage;
        return .{ .listener_id = std.mem.readInt(u32, p[0..4], .big), .peer = try Endpoint.decode(p[4..]) };
    }
};

/// Converts a wire endpoint to a socket address.
pub fn endpointAddress(ep: Endpoint) std.net.Address {
    if (ep.addr.len == 4) return std.net.Address.initIp4(ep.addr[0..4].*, ep.port);
    return std.net.Address.initIp6(ep.addr[0..16].*, ep.port, 0, 0);
}

/// Encodes a socket address as an endpoint (`storage` backs the address bytes).
pub fn addressEndpoint(transport: Transport, addr: std.net.Address, storage: *[16]u8) Endpoint {
    switch (addr.any.family) {
        std.posix.AF.INET6 => {
            storage.* = addr.in6.sa.addr;
            return .{ .transport = transport, .addr = storage[0..16], .port = addr.getPort() };
        },
        else => {
            storage[0..4].* = std.mem.asBytes(&addr.in.sa.addr).*;
            return .{ .transport = transport, .addr = storage[0..4], .port = addr.getPort() };
        },
    }
}

test "accepted round trip" {
    var buf: [Accepted.max_len]u8 = undefined;
    var st: [16]u8 = undefined;
    const peer = addressEndpoint(.udp, std.net.Address.initIp4(.{ 192, 168, 1, 7 }, 5353), &st);
    const dec = try Accepted.decode((Accepted{ .listener_id = 9, .peer = peer }).encode(&buf));
    try std.testing.expectEqual(@as(u32, 9), dec.listener_id);
    try std.testing.expectEqual(Transport.udp, dec.peer.transport);
    try std.testing.expect(endpointAddress(dec.peer).eql(std.net.Address.initIp4(.{ 192, 168, 1, 7 }, 5353)));
    const e = try IcmpEcho.decode(&(IcmpEcho{ .addr = .{ 10, 0, 0, 1 }, .timeout_ms = 900 }).encode());
    try std.testing.expectEqual(@as(u16, 900), e.timeout_ms);
}

test "connect request round trip" {
    var buf: [ConnectRequest.max_len]u8 = undefined;
    const enc = (ConnectRequest{ .transport = .tcp, .addr = &.{ 10, 0, 0, 1 }, .port = 445 }).encode(&buf);
    const dec = try ConnectRequest.decode(enc);
    try std.testing.expectEqual(Transport.tcp, dec.transport);
    try std.testing.expectEqual(@as(u16, 445), dec.port);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, dec.addr);
    try std.testing.expectEqual(@as(u16, 0), dec.timeout_ms);

    const enc2 = (ConnectRequest{ .transport = .tcp, .addr = &.{ 10, 0, 0, 2 }, .port = 22, .timeout_ms = 2500 }).encode(&buf);
    try std.testing.expectEqual(@as(u16, 2500), (try ConnectRequest.decode(enc2)).timeout_ms);
    try std.testing.expectError(error.InvalidMessage, ConnectRequest.decode(enc2[0 .. enc2.len - 1]));
}

test "fail reason mapping" {
    try std.testing.expectEqual(FailReason.refused, FailReason.fromError(error.ConnectionRefused));
    try std.testing.expectEqual(FailReason.timeout, FailReason.fromError(error.ConnectionTimedOut));
    try std.testing.expectEqual(FailReason.unreachable_net, FailReason.fromError(error.NetworkUnreachable));
    try std.testing.expectEqual(FailReason.unreachable_host, FailReason.fromError(error.HostUnreachable));
    try std.testing.expectEqual(FailReason.prohibited, FailReason.fromError(error.AccessDenied));
}
