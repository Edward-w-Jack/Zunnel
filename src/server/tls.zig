//! TLS 1.3 on zunnel-server's listening port, so new connections look
//! like HTTPS on the wire. Noise still authenticates inside, so the TLS
//! layer here is camouflage: a self-signed cert is generated on first run.
//!
//! Backed by mbedTLS 3.6 (fetched via `build.zig.zon`). The agent uses
//! Zig std's `crypto.tls.Client`, so neither library has to know about the
//! other beyond agreeing on TLS 1.3 + X25519 + AES-128-GCM-SHA256.
const std = @import("std");
const builtin = @import("builtin");
const common = @import("common");
const sock = common.sock;
const Stream = common.stream.Stream;
const stream_mod = common.stream;

const log = std.log.scoped(.tls);

const c = @cImport({
    @cDefine("MBEDTLS_ALLOW_PRIVATE_ACCESS", "1");
    @cInclude("mbedtls/ssl.h");
    @cInclude("mbedtls/ctr_drbg.h");
    @cInclude("mbedtls/entropy.h");
    @cInclude("mbedtls/net_sockets.h"); // for MBEDTLS_ERR_NET_* constants
    @cInclude("mbedtls/pk.h");
    @cInclude("mbedtls/ecp.h");
    @cInclude("mbedtls/x509.h");
    @cInclude("mbedtls/x509_crt.h");
    @cInclude("mbedtls/error.h");
    @cInclude("mbedtls/debug.h");
    @cInclude("psa/crypto.h");
});

const cert_days: u32 = 397;

/// Mapped from any mbedTLS error we can't recover from. The caller logs the
/// specific code via `logMbedErr`.
pub const Error = error{
    TlsFailure,
    OutOfMemory,
    CertificateGenerationFailed,
    InvalidCertificateFile,
};

fn logMbedErr(prefix: []const u8, ret: c_int) void {
    var buf: [128]u8 = undefined;
    c.mbedtls_strerror(ret, &buf, buf.len);
    const text = std.mem.sliceTo(&buf, 0);
    log.err("{s}: {s} (-0x{x:0>4})", .{ prefix, text, @as(u32, @intCast(-ret)) });
}

/// Shared state for every TLS session the server accepts: the certificate
/// chain, the private key, the shared config, and a seeded CTR_DRBG.
pub const Server = struct {
    gpa: std.mem.Allocator,
    conf: c.mbedtls_ssl_config,
    cert: c.mbedtls_x509_crt,
    key: c.mbedtls_pk_context,
    entropy: c.mbedtls_entropy_context,
    drbg: c.mbedtls_ctr_drbg_context,
    psa_inited: bool,

    /// Loads the certificate and key, generating a self-signed pair if either
    /// file is missing. Writes `cert_path` and `key_path` with mode 0600.
    pub fn init(gpa: std.mem.Allocator, cert_path: []const u8, key_path: []const u8) !*Server {
        const self = try gpa.create(Server);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .conf = std.mem.zeroes(c.mbedtls_ssl_config),
            .cert = std.mem.zeroes(c.mbedtls_x509_crt),
            .key = std.mem.zeroes(c.mbedtls_pk_context),
            .entropy = std.mem.zeroes(c.mbedtls_entropy_context),
            .drbg = std.mem.zeroes(c.mbedtls_ctr_drbg_context),
            .psa_inited = false,
        };

        c.mbedtls_ssl_config_init(&self.conf);
        c.mbedtls_x509_crt_init(&self.cert);
        c.mbedtls_pk_init(&self.key);
        c.mbedtls_entropy_init(&self.entropy);
        c.mbedtls_ctr_drbg_init(&self.drbg);
        errdefer self.freeMbed();

        {
            const psa_rc = c.psa_crypto_init();
            if (psa_rc != 0) {
                log.err("psa_crypto_init failed: {d}", .{psa_rc});
                return error.TlsFailure;
            }
            self.psa_inited = true;
        }

        const seed = "zunnel-server-tls";
        var ret = c.mbedtls_ctr_drbg_seed(&self.drbg, c.mbedtls_entropy_func, &self.entropy, seed, seed.len);
        if (ret != 0) {
            logMbedErr("ctr_drbg_seed", ret);
            return error.TlsFailure;
        }

        try self.loadOrGenerateCert(cert_path, key_path);

        ret = c.mbedtls_ssl_config_defaults(&self.conf, c.MBEDTLS_SSL_IS_SERVER, c.MBEDTLS_SSL_TRANSPORT_STREAM, c.MBEDTLS_SSL_PRESET_DEFAULT);
        if (ret != 0) {
            logMbedErr("ssl_config_defaults", ret);
            return error.TlsFailure;
        }
        c.mbedtls_ssl_conf_rng(&self.conf, c.mbedtls_ctr_drbg_random, &self.drbg);
        c.mbedtls_ssl_conf_min_tls_version(&self.conf, c.MBEDTLS_SSL_VERSION_TLS1_3);
        c.mbedtls_ssl_conf_max_tls_version(&self.conf, c.MBEDTLS_SSL_VERSION_TLS1_3);
        // Clients never present a certificate; Noise authenticates the agent.
        c.mbedtls_ssl_conf_authmode(&self.conf, c.MBEDTLS_SSL_VERIFY_NONE);
        ret = c.mbedtls_ssl_conf_own_cert(&self.conf, &self.cert, &self.key);
        if (ret != 0) {
            logMbedErr("ssl_conf_own_cert", ret);
            return error.TlsFailure;
        }
        return self;
    }

    pub fn deinit(self: *Server) void {
        self.freeMbed();
        self.gpa.destroy(self);
    }

    fn freeMbed(self: *Server) void {
        c.mbedtls_ssl_config_free(&self.conf);
        c.mbedtls_x509_crt_free(&self.cert);
        c.mbedtls_pk_free(&self.key);
        c.mbedtls_ctr_drbg_free(&self.drbg);
        c.mbedtls_entropy_free(&self.entropy);
        if (self.psa_inited) {
            c.mbedtls_psa_crypto_free();
            self.psa_inited = false;
        }
    }

    /// Takes ownership of `handle`, performs the TLS handshake and returns a
    /// Stream wrapping the TLS session. On failure the handle is closed.
    pub fn accept(self: *Server, handle: sock.Handle) !Stream {
        const conn = self.gpa.create(TlsConn) catch |err| {
            sock.close(handle);
            return err;
        };
        errdefer self.gpa.destroy(conn);
        conn.* = .{ .gpa = self.gpa, .handle = handle, .ssl = std.mem.zeroes(c.mbedtls_ssl_context) };
        c.mbedtls_ssl_init(&conn.ssl);
        errdefer c.mbedtls_ssl_free(&conn.ssl);

        var ret = c.mbedtls_ssl_setup(&conn.ssl, &self.conf);
        if (ret != 0) {
            logMbedErr("ssl_setup", ret);
            sock.close(handle);
            return error.TlsFailure;
        }
        c.mbedtls_ssl_set_bio(&conn.ssl, conn, bioSend, bioRecv, null);

        // Blocking sockets: a single handshake call returns when done or when
        // the peer gave up. The caller has set a recv timeout on the handle.
        while (true) {
            ret = c.mbedtls_ssl_handshake(&conn.ssl);
            switch (ret) {
                0 => break,
                c.MBEDTLS_ERR_SSL_WANT_READ, c.MBEDTLS_ERR_SSL_WANT_WRITE => continue,
                else => {
                    logMbedErr("ssl_handshake", ret);
                    sock.close(handle);
                    return error.TlsFailure;
                },
            }
        }
        return .{ .ctx = conn, .vtable = &conn_vtable };
    }

    /// Returns a hex SHA-256 fingerprint of the loaded certificate, for the
    /// banner. Null on allocation failure.
    pub fn certFingerprint(self: *Server) ?[64]u8 {
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(self.cert.raw.p[0..self.cert.raw.len], &hash, .{});
        return std.fmt.bytesToHex(&hash, .lower);
    }

    // -------------------------------------------------- cert load / generate

    fn loadOrGenerateCert(self: *Server, cert_path: []const u8, key_path: []const u8) !void {
        if (std.fs.cwd().access(cert_path, .{}) catch null != null and
            std.fs.cwd().access(key_path, .{}) catch null != null)
        {
            try self.loadCert(cert_path, key_path);
            return;
        }
        try self.generateSelfSigned(cert_path, key_path);
        try self.loadCert(cert_path, key_path);
    }

    fn loadCert(self: *Server, cert_path: []const u8, key_path: []const u8) !void {
        const cert_z = try self.gpa.dupeZ(u8, cert_path);
        defer self.gpa.free(cert_z);
        const key_z = try self.gpa.dupeZ(u8, key_path);
        defer self.gpa.free(key_z);
        var ret = c.mbedtls_x509_crt_parse_file(&self.cert, cert_z.ptr);
        if (ret != 0) {
            logMbedErr("parse_cert", ret);
            return error.InvalidCertificateFile;
        }
        ret = c.mbedtls_pk_parse_keyfile(&self.key, key_z.ptr, null, c.mbedtls_ctr_drbg_random, &self.drbg);
        if (ret != 0) {
            logMbedErr("parse_key", ret);
            return error.InvalidCertificateFile;
        }
    }

    /// ECDSA P-256 self-signed cert, CN=localhost, 397-day validity.
    /// Writes PEM files for both cert and private key, mode 0600 on POSIX.
    fn generateSelfSigned(self: *Server, cert_path: []const u8, key_path: []const u8) !void {
        log.info("generating self-signed TLS cert ({s}, {s})", .{ cert_path, key_path });
        var key: c.mbedtls_pk_context = std.mem.zeroes(c.mbedtls_pk_context);
        c.mbedtls_pk_init(&key);
        defer c.mbedtls_pk_free(&key);

        var ret = c.mbedtls_pk_setup(&key, c.mbedtls_pk_info_from_type(c.MBEDTLS_PK_ECKEY));
        if (ret != 0) {
            logMbedErr("pk_setup", ret);
            return error.CertificateGenerationFailed;
        }
        ret = c.mbedtls_ecp_gen_key(c.MBEDTLS_ECP_DP_SECP256R1, c.mbedtls_pk_ec(key), c.mbedtls_ctr_drbg_random, &self.drbg);
        if (ret != 0) {
            logMbedErr("ecp_gen_key", ret);
            return error.CertificateGenerationFailed;
        }

        var crt: c.mbedtls_x509write_cert = std.mem.zeroes(c.mbedtls_x509write_cert);
        c.mbedtls_x509write_crt_init(&crt);
        defer c.mbedtls_x509write_crt_free(&crt);

        c.mbedtls_x509write_crt_set_version(&crt, c.MBEDTLS_X509_CRT_VERSION_3);
        c.mbedtls_x509write_crt_set_subject_key(&crt, &key);
        c.mbedtls_x509write_crt_set_issuer_key(&crt, &key);
        c.mbedtls_x509write_crt_set_md_alg(&crt, c.MBEDTLS_MD_SHA256);

        ret = c.mbedtls_x509write_crt_set_subject_name(&crt, "CN=localhost");
        if (ret != 0) {
            logMbedErr("set_subject", ret);
            return error.CertificateGenerationFailed;
        }
        ret = c.mbedtls_x509write_crt_set_issuer_name(&crt, "CN=localhost");
        if (ret != 0) {
            logMbedErr("set_issuer", ret);
            return error.CertificateGenerationFailed;
        }

        var serial: [16]u8 = undefined;
        std.crypto.random.bytes(&serial);
        serial[0] &= 0x7f; // positive
        ret = c.mbedtls_x509write_crt_set_serial_raw(&crt, &serial, serial.len);
        if (ret != 0) {
            logMbedErr("set_serial", ret);
            return error.CertificateGenerationFailed;
        }

        // Validity: last week → +397 days. "YYYYMMDDHHMMSS" ASCII.
        var not_before: [15]u8 = undefined;
        var not_after: [15]u8 = undefined;
        formatValidity(&not_before, std.time.timestamp() - 7 * std.time.s_per_day);
        formatValidity(&not_after, std.time.timestamp() + @as(i64, cert_days) * std.time.s_per_day);
        ret = c.mbedtls_x509write_crt_set_validity(&crt, &not_before, &not_after);
        if (ret != 0) {
            logMbedErr("set_validity", ret);
            return error.CertificateGenerationFailed;
        }

        ret = c.mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
        if (ret != 0) {
            logMbedErr("set_basic_constraints", ret);
            return error.CertificateGenerationFailed;
        }
        ret = c.mbedtls_x509write_crt_set_key_usage(&crt, c.MBEDTLS_X509_KU_DIGITAL_SIGNATURE | c.MBEDTLS_X509_KU_KEY_ENCIPHERMENT);
        if (ret != 0) {
            logMbedErr("set_key_usage", ret);
            return error.CertificateGenerationFailed;
        }
        ret = c.mbedtls_x509write_crt_set_subject_key_identifier(&crt);
        if (ret != 0) {
            logMbedErr("set_subject_key_id", ret);
            return error.CertificateGenerationFailed;
        }

        var cert_pem: [4096]u8 = undefined;
        ret = c.mbedtls_x509write_crt_pem(&crt, &cert_pem, cert_pem.len, c.mbedtls_ctr_drbg_random, &self.drbg);
        if (ret != 0) {
            logMbedErr("crt_pem", ret);
            return error.CertificateGenerationFailed;
        }
        const cert_len = std.mem.indexOfScalar(u8, &cert_pem, 0) orelse cert_pem.len;

        var key_pem: [1024]u8 = undefined;
        ret = c.mbedtls_pk_write_key_pem(&key, &key_pem, key_pem.len);
        if (ret != 0) {
            logMbedErr("pk_write_key_pem", ret);
            return error.CertificateGenerationFailed;
        }
        const key_len = std.mem.indexOfScalar(u8, &key_pem, 0) orelse key_pem.len;

        try writeSecret(cert_path, cert_pem[0..cert_len]);
        try writeSecret(key_path, key_pem[0..key_len]);
    }
};

/// POSIX writes 0600; Windows inherits ACLs from the parent, which is fine
/// for an operator machine.
fn writeSecret(path: []const u8, data: []const u8) !void {
    if (builtin.os.tag == .windows) {
        try std.fs.cwd().writeFile(.{ .sub_path = path, .data = data });
        return;
    }
    const file = try std.fs.cwd().createFile(path, .{ .truncate = true, .mode = 0o600 });
    defer file.close();
    try file.writeAll(data);
}

/// Formats a Unix seconds timestamp as `YYYYMMDDHHMMSS` (14 ASCII bytes),
/// NUL-terminated into a 15-byte buffer (what mbedTLS wants).
fn formatValidity(out: *[15]u8, unix_s: i64) void {
    const secs: u64 = @intCast(@max(0, unix_s));
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    _ = std.fmt.bufPrint(out, "{d:0>4}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}\x00", .{
        yd.year,                 md.month.numeric(),      @as(u8, md.day_index) + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

// --------------------------------------------------------- per connection

const TlsConn = struct {
    gpa: std.mem.Allocator,
    handle: sock.Handle,
    ssl: c.mbedtls_ssl_context,
};

const conn_vtable: Stream.VTable = .{
    .recv = recvFn,
    .sendAll = sendAllFn,
    .shutdown = shutdownFn,
    .close = closeFn,
    .setRecvTimeout = setRecvTimeoutFn,
    .setSendTimeout = setSendTimeoutFn,
};

fn connFromCtx(ctx: *anyopaque) *TlsConn {
    return @ptrCast(@alignCast(ctx));
}

/// mbedTLS BIO receive: deliver bytes from the underlying TCP socket.
fn bioRecv(ctx: ?*anyopaque, buf: [*c]u8, len: usize) callconv(.c) c_int {
    const conn = connFromCtx(ctx.?);
    const n = sock.recv(conn.handle, buf[0..len]) catch |err| return switch (err) {
        error.Timeout => c.MBEDTLS_ERR_SSL_WANT_READ,
        error.ConnectionReset => c.MBEDTLS_ERR_NET_CONN_RESET,
        error.RecvFailed => c.MBEDTLS_ERR_NET_RECV_FAILED,
    };
    if (n == 0) return c.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
    return @intCast(n);
}

/// mbedTLS BIO send: push bytes down to the TCP socket.
fn bioSend(ctx: ?*anyopaque, buf: [*c]const u8, len: usize) callconv(.c) c_int {
    const conn = connFromCtx(ctx.?);
    const n = sock.send(conn.handle, buf[0..len]) catch return c.MBEDTLS_ERR_NET_SEND_FAILED;
    return @intCast(n);
}

fn recvFn(ctx: *anyopaque, buf: []u8) stream_mod.RecvError!usize {
    const conn = connFromCtx(ctx);
    const ret = c.mbedtls_ssl_read(&conn.ssl, buf.ptr, buf.len);
    if (ret > 0) return @intCast(ret);
    return switch (ret) {
        0, c.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => 0,
        c.MBEDTLS_ERR_NET_CONN_RESET => error.ConnectionReset,
        c.MBEDTLS_ERR_SSL_WANT_READ, c.MBEDTLS_ERR_SSL_WANT_WRITE => error.Timeout,
        else => blk: {
            logMbedErr("ssl_read", ret);
            break :blk error.TlsFailure;
        },
    };
}

fn sendAllFn(ctx: *anyopaque, data: []const u8) stream_mod.SendError!void {
    const conn = connFromCtx(ctx);
    var off: usize = 0;
    while (off < data.len) {
        const ret = c.mbedtls_ssl_write(&conn.ssl, data.ptr + off, data.len - off);
        if (ret > 0) {
            off += @intCast(ret);
            continue;
        }
        if (ret == c.MBEDTLS_ERR_SSL_WANT_READ or ret == c.MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (ret == c.MBEDTLS_ERR_NET_CONN_RESET) return error.ConnectionReset;
        logMbedErr("ssl_write", ret);
        return error.TlsFailure;
    }
}

fn shutdownFn(ctx: *anyopaque, how: sock.How) void {
    const conn = connFromCtx(ctx);
    sock.shutdown(conn.handle, how);
}

fn closeFn(ctx: *anyopaque) void {
    const conn = connFromCtx(ctx);
    _ = c.mbedtls_ssl_close_notify(&conn.ssl);
    c.mbedtls_ssl_free(&conn.ssl);
    sock.close(conn.handle);
    conn.gpa.destroy(conn);
}

fn setRecvTimeoutFn(ctx: *anyopaque, ms: u32) void {
    sock.setRecvTimeout(connFromCtx(ctx).handle, ms);
}

fn setSendTimeoutFn(ctx: *anyopaque, ms: u32) void {
    sock.setSendTimeout(connFromCtx(ctx).handle, ms);
}

test formatValidity {
    var out: [15]u8 = undefined;
    // 2026-10-20T18:00:00Z
    formatValidity(&out, 1792519200);
    try std.testing.expectEqualStrings("20261020180000", out[0..14]);
    try std.testing.expectEqual(@as(u8, 0), out[14]);
}

// -------------------------------------------------------- integration test

const TlsServerFixture = struct {
    srv: *Server,
    listener: *std.net.Server,
    err: ?anyerror = null,
    stream: ?Stream = null,

    fn run(self: *TlsServerFixture) void {
        self.runInner() catch |err| {
            self.err = err;
        };
    }

    fn runInner(self: *TlsServerFixture) !void {
        const conn = try self.listener.accept();
        sock.setRecvTimeout(conn.stream.handle, 10_000);
        self.stream = try self.srv.accept(conn.stream.handle);
        var buf: [5]u8 = undefined;
        try self.stream.?.recvExact(&buf);
        try std.testing.expectEqualStrings("hello", &buf);
        try self.stream.?.sendAll("world");
    }
};

test "server TLS: self-signed cert + handshake against std.crypto.tls.Client" {
    // Use a scratch directory for the generated cert/key files so repeated
    // runs don't leave anything in the repo root.
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cert_path = try tmp.dir.realpathAlloc(gpa, ".");
    defer gpa.free(cert_path);
    const cert_file = try std.fs.path.join(gpa, &.{ cert_path, "cert.pem" });
    defer gpa.free(cert_file);
    const key_file = try std.fs.path.join(gpa, &.{ cert_path, "key.pem" });
    defer gpa.free(key_file);

    const srv = try Server.init(gpa, cert_file, key_file);
    defer srv.deinit();

    // Loading twice reads the generated files back without regenerating.
    const srv2 = try Server.init(gpa, cert_file, key_file);
    srv2.deinit();

    var listener = try sock.listenTcp(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0), 1);
    defer listener.deinit();
    var fx: TlsServerFixture = .{ .srv = srv, .listener = &listener };
    const t = try std.Thread.spawn(.{}, TlsServerFixture.run, .{&fx});

    // Agent side (what phase 5 wires up for real).
    const client_handle = try sock.tcpConnect(listener.listen_address, 5000);
    const tcp = std.net.Stream{ .handle = client_handle };
    defer tcp.close();
    const min_tls_buf = std.crypto.tls.Client.min_buffer_len;
    var tcp_rbuf: [min_tls_buf]u8 = undefined;
    var tcp_wbuf: [min_tls_buf]u8 = undefined;
    var tls_rbuf: [min_tls_buf]u8 = undefined;
    var tls_wbuf: [min_tls_buf]u8 = undefined;
    var tcp_reader = tcp.reader(&tcp_rbuf);
    var tcp_writer = tcp.writer(&tcp_wbuf);
    var tls_client = try std.crypto.tls.Client.init(tcp_reader.interface(), &tcp_writer.interface, .{
        .host = .no_verification,
        .ca = .no_verification,
        .read_buffer = &tls_rbuf,
        .write_buffer = &tls_wbuf,
    });
    try tls_client.writer.writeAll("hello");
    try tls_client.writer.flush();
    // std.crypto.tls.Client's own flush only hands ciphertext to `output`'s
    // buffer; the underlying TCP writer must still be flushed to the socket.
    try tcp_writer.interface.flush();
    var got: [5]u8 = undefined;
    try tls_client.reader.readSliceAll(&got);
    try std.testing.expectEqualStrings("world", &got);

    t.join();
    if (fx.err) |err| return err;
    if (fx.stream) |s| s.close();
}
