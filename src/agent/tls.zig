//! TLS client on the agent side, powered by Zig's `std.crypto.tls.Client`.
//! The Stream it returns is what the Noise handshake runs over, so from
//! `link.zig`'s viewpoint there's no difference between TCP and TLS.
//!
//! The Noise handshake inside already authenticates the proxy, so hostname
//! and CA verification are off by default (`host: .no_verification`,
//! `ca: .no_verification`). `-tls-verify` and `-ca` enable them for operators
//! who want TLS to look like a normal HTTPS client, with a real cert chain.
const std = @import("std");
const common = @import("common");

const sock = common.sock;
const Stream = common.stream.Stream;
const stream_mod = common.stream;

const log = std.log.scoped(.tls);

const min_buf = std.crypto.tls.Client.min_buffer_len;

pub const Options = struct {
    /// Set to the hostname when hostname verification is wanted (-tls-verify).
    host: ?[]const u8 = null,
    /// A trust bundle to verify the proxy's cert against (-ca <file>).
    ca: ?std.crypto.Certificate.Bundle = null,
};

pub const Error = error{TlsHandshakeFailed} || std.mem.Allocator.Error;

/// Takes ownership of `handle`: the returned Stream closes the socket and
/// frees the backing on `close`. On handshake failure the handle is closed
/// too, and the error is logged.
pub fn connect(gpa: std.mem.Allocator, handle: sock.Handle, options: Options) Error!Stream {
    const self = gpa.create(TlsStream) catch |err| {
        sock.close(handle);
        return err;
    };
    errdefer gpa.destroy(self);
    self.* = .{
        .gpa = gpa,
        .handle = handle,
        .tcp_reader = undefined,
        .tcp_writer = undefined,
        .client = undefined,
        .tcp_rbuf = undefined,
        .tcp_wbuf = undefined,
        .tls_rbuf = undefined,
        .tls_wbuf = undefined,
    };
    const net_stream: std.net.Stream = .{ .handle = handle };
    self.tcp_reader = net_stream.reader(&self.tcp_rbuf);
    self.tcp_writer = net_stream.writer(&self.tcp_wbuf);

    self.client = std.crypto.tls.Client.init(self.tcp_reader.interface(), &self.tcp_writer.interface, .{
        .host = if (options.host) |h| .{ .explicit = h } else .no_verification,
        .ca = if (options.ca) |b| .{ .bundle = b } else .no_verification,
        .read_buffer = &self.tls_rbuf,
        .write_buffer = &self.tls_wbuf,
    }) catch |err| {
        log.err("TLS handshake failed: {s}", .{@errorName(err)});
        sock.close(handle);
        return error.TlsHandshakeFailed;
    };
    return .{ .ctx = self, .vtable = &vtable };
}

const TlsStream = struct {
    gpa: std.mem.Allocator,
    handle: sock.Handle,
    tcp_reader: std.net.Stream.Reader,
    tcp_writer: std.net.Stream.Writer,
    client: std.crypto.tls.Client,
    tcp_rbuf: [min_buf]u8,
    tcp_wbuf: [min_buf]u8,
    tls_rbuf: [min_buf]u8,
    tls_wbuf: [min_buf]u8,
};

const vtable: Stream.VTable = .{
    .recv = recvFn,
    .sendAll = sendAllFn,
    .shutdown = shutdownFn,
    .close = closeFn,
    .setRecvTimeout = setRecvTimeoutFn,
    .setSendTimeout = setSendTimeoutFn,
};

fn selfFromCtx(ctx: *anyopaque) *TlsStream {
    return @ptrCast(@alignCast(ctx));
}

fn recvFn(ctx: *anyopaque, buf: []u8) stream_mod.RecvError!usize {
    const self = selfFromCtx(ctx);
    // Reader.readSliceShort is "0+" but doesn't throw EndOfStream; it just
    // returns a short read (possibly 0) when the stream ends.
    const n = self.client.reader.readSliceShort(buf) catch |err| {
        log.err("TLS read: {s}", .{@errorName(err)});
        return error.TlsFailure;
    };
    return n;
}

fn sendAllFn(ctx: *anyopaque, data: []const u8) stream_mod.SendError!void {
    const self = selfFromCtx(ctx);
    self.client.writer.writeAll(data) catch return error.TlsFailure;
    self.client.writer.flush() catch return error.TlsFailure;
    // The TLS writer only buffers ciphertext in the TCP writer; push it out.
    self.tcp_writer.interface.flush() catch return error.TlsFailure;
}

fn shutdownFn(ctx: *anyopaque, how: sock.How) void {
    sock.shutdown(selfFromCtx(ctx).handle, how);
}

fn closeFn(ctx: *anyopaque) void {
    const self = selfFromCtx(ctx);
    self.client.end() catch {};
    _ = self.tcp_writer.interface.flush() catch {};
    sock.close(self.handle);
    self.gpa.destroy(self);
}

fn setRecvTimeoutFn(ctx: *anyopaque, ms: u32) void {
    sock.setRecvTimeout(selfFromCtx(ctx).handle, ms);
}

fn setSendTimeoutFn(ctx: *anyopaque, ms: u32) void {
    sock.setSendTimeout(selfFromCtx(ctx).handle, ms);
}
