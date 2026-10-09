//! Noise_NKpsk0_25519_ChaChaPoly_BLAKE2s (https://noiseprotocol.org/noise.html)
//!
//!   NKpsk0:
//!     <- s
//!     ...
//!     -> psk, e, es
//!     <- e, ee
//!
//! The agent (initiator) knows the proxy's static key up front. The psk is
//! mixed in before message 1, so the proxy rejects an agent with the wrong
//! secret before accepting it. When no secret is configured an all-zero psk is
//! used, which degrades to plain NK security.
const std = @import("std");
const crypto = std.crypto;

const X25519 = crypto.dh.X25519;
const Aead = crypto.aead.chacha_poly.ChaCha20Poly1305;
const Blake2s = crypto.hash.blake2.Blake2s256;
const Hmac = crypto.auth.hmac.Hmac(Blake2s);

pub const protocol_name = "Noise_NKpsk0_25519_ChaChaPoly_BLAKE2s";
pub const key_len = 32;
pub const tag_len = Aead.tag_length;
pub const KeyPair = X25519.KeyPair;

pub const Error = error{ AuthenticationFailed, InvalidMessage, WeakPublicKey, NonceExhausted };

/// Derives the 32-byte psk from a user-supplied secret ("" -> all zeros).
pub fn pskFromSecret(secret: []const u8) [key_len]u8 {
    if (secret.len == 0) return [_]u8{0} ** key_len;
    var out: [key_len]u8 = undefined;
    var h = Blake2s.init(.{});
    h.update("zunnel-psk-v1:");
    h.update(secret);
    h.final(&out);
    return out;
}

/// A transport cipher for one direction of the session.
pub const CipherState = struct {
    k: [key_len]u8,
    n: u64 = 0,

    /// Encrypts `plaintext` into `out`, which must be `plaintext.len + tag_len` long.
    pub fn encrypt(self: *CipherState, out: []u8, ad: []const u8, plaintext: []const u8) Error!void {
        std.debug.assert(out.len == plaintext.len + tag_len);
        if (self.n == std.math.maxInt(u64)) return error.NonceExhausted;
        Aead.encrypt(out[0..plaintext.len], out[plaintext.len..][0..tag_len], plaintext, ad, nonce(self.n), self.k);
        self.n += 1;
    }

    /// Decrypts `ciphertext` into `out`, which must be `ciphertext.len - tag_len` long.
    /// `out` may alias the start of `ciphertext`.
    pub fn decrypt(self: *CipherState, out: []u8, ad: []const u8, ciphertext: []const u8) Error!void {
        if (ciphertext.len < tag_len) return error.InvalidMessage;
        const body_len = ciphertext.len - tag_len;
        std.debug.assert(out.len == body_len);
        if (self.n == std.math.maxInt(u64)) return error.NonceExhausted;
        const tag = ciphertext[body_len..][0..tag_len].*;
        Aead.decrypt(out, ciphertext[0..body_len], tag, ad, nonce(self.n), self.k) catch
            return error.AuthenticationFailed;
        self.n += 1;
    }
};

fn nonce(n: u64) [Aead.nonce_length]u8 {
    var b = [_]u8{0} ** Aead.nonce_length;
    std.mem.writeInt(u64, b[4..12], n, .little);
    return b;
}

fn hkdf(ck: *const [32]u8, ikm: []const u8, comptime n: usize) [n][32]u8 {
    var temp: [32]u8 = undefined;
    Hmac.create(&temp, ikm, ck);
    var out: [n][32]u8 = undefined;
    for (0..n) |i| {
        var m = Hmac.init(&temp);
        if (i > 0) m.update(&out[i - 1]);
        m.update(&[_]u8{@intCast(i + 1)});
        m.final(&out[i]);
    }
    return out;
}

const SymmetricState = struct {
    ck: [32]u8,
    h: [32]u8,
    cs: ?CipherState = null,

    fn init(prologue: []const u8) SymmetricState {
        var h: [32]u8 = undefined;
        // protocol_name is longer than HASHLEN, so h = HASH(protocol_name).
        Blake2s.hash(protocol_name, &h, .{});
        var ss: SymmetricState = .{ .ck = h, .h = h };
        ss.mixHash(prologue);
        return ss;
    }

    fn mixHash(self: *SymmetricState, data: []const u8) void {
        var hasher = Blake2s.init(.{});
        hasher.update(&self.h);
        hasher.update(data);
        hasher.final(&self.h);
    }

    fn mixKey(self: *SymmetricState, ikm: []const u8) void {
        const out = hkdf(&self.ck, ikm, 2);
        self.ck = out[0];
        self.cs = .{ .k = out[1] };
    }

    fn mixKeyAndHash(self: *SymmetricState, ikm: []const u8) void {
        const out = hkdf(&self.ck, ikm, 3);
        self.ck = out[0];
        self.mixHash(&out[1]);
        self.cs = .{ .k = out[2] };
    }

    fn encryptAndHash(self: *SymmetricState, out: []u8, plaintext: []const u8) Error!void {
        if (self.cs) |*cs| {
            try cs.encrypt(out, &self.h, plaintext);
        } else {
            @memcpy(out, plaintext);
        }
        self.mixHash(out);
    }

    fn decryptAndHash(self: *SymmetricState, out: []u8, ciphertext: []const u8) Error!void {
        const h = self.h;
        if (self.cs) |*cs| {
            try cs.decrypt(out, &h, ciphertext);
        } else {
            @memcpy(out, ciphertext);
        }
        self.mixHash(ciphertext);
    }

    fn split(self: *SymmetricState) [2]CipherState {
        const out = hkdf(&self.ck, "", 2);
        return .{ .{ .k = out[0] }, .{ .k = out[1] } };
    }
};

pub const Transport = struct {
    send: CipherState,
    recv: CipherState,
};

/// Length of handshake message 1/2 for a given payload length.
pub fn messageLen(payload_len: usize) usize {
    return key_len + payload_len + tag_len;
}

pub const Initiator = struct {
    ss: SymmetricState,
    rs: [key_len]u8,
    psk: [key_len]u8,
    e: KeyPair = undefined,

    pub fn init(remote_static: [key_len]u8, psk: [key_len]u8, prologue: []const u8) Initiator {
        var ss = SymmetricState.init(prologue);
        ss.mixHash(&remote_static);
        return .{ .ss = ss, .rs = remote_static, .psk = psk };
    }

    /// -> psk, e, es   (payload is encrypted, but not yet forward secret)
    pub fn writeMessage1(self: *Initiator, out: []u8, payload: []const u8) Error![]u8 {
        const len = messageLen(payload.len);
        if (out.len < len) return error.InvalidMessage;
        self.ss.mixKeyAndHash(&self.psk);
        self.e = KeyPair.generate();
        out[0..key_len].* = self.e.public_key;
        self.ss.mixHash(&self.e.public_key);
        self.ss.mixKey(&self.e.public_key); // psk modifier
        const es = X25519.scalarmult(self.e.secret_key, self.rs) catch return error.WeakPublicKey;
        self.ss.mixKey(&es);
        try self.ss.encryptAndHash(out[key_len..len], payload);
        return out[0..len];
    }

    /// <- e, ee
    pub fn readMessage2(self: *Initiator, msg: []const u8, payload_out: []u8) Error!struct { Transport, []u8 } {
        if (msg.len < key_len + tag_len) return error.InvalidMessage;
        const re = msg[0..key_len].*;
        self.ss.mixHash(&re);
        self.ss.mixKey(&re);
        const ee = X25519.scalarmult(self.e.secret_key, re) catch return error.WeakPublicKey;
        self.ss.mixKey(&ee);
        const plen = msg.len - key_len - tag_len;
        if (payload_out.len < plen) return error.InvalidMessage;
        try self.ss.decryptAndHash(payload_out[0..plen], msg[key_len..]);
        const cs = self.ss.split();
        return .{ .{ .send = cs[0], .recv = cs[1] }, payload_out[0..plen] };
    }
};

pub const Responder = struct {
    ss: SymmetricState,
    s: KeyPair,
    psk: [key_len]u8,
    re: [key_len]u8 = undefined,

    pub fn init(static: KeyPair, psk: [key_len]u8, prologue: []const u8) Responder {
        var ss = SymmetricState.init(prologue);
        ss.mixHash(&static.public_key);
        return .{ .ss = ss, .s = static, .psk = psk };
    }

    /// -> psk, e, es
    pub fn readMessage1(self: *Responder, msg: []const u8, payload_out: []u8) Error![]u8 {
        if (msg.len < key_len + tag_len) return error.InvalidMessage;
        self.ss.mixKeyAndHash(&self.psk);
        self.re = msg[0..key_len].*;
        self.ss.mixHash(&self.re);
        self.ss.mixKey(&self.re);
        const es = X25519.scalarmult(self.s.secret_key, self.re) catch return error.WeakPublicKey;
        self.ss.mixKey(&es);
        const plen = msg.len - key_len - tag_len;
        if (payload_out.len < plen) return error.InvalidMessage;
        try self.ss.decryptAndHash(payload_out[0..plen], msg[key_len..]);
        return payload_out[0..plen];
    }

    /// <- e, ee
    pub fn writeMessage2(self: *Responder, out: []u8, payload: []const u8) Error!struct { Transport, []u8 } {
        const len = messageLen(payload.len);
        if (out.len < len) return error.InvalidMessage;
        const e = KeyPair.generate();
        out[0..key_len].* = e.public_key;
        self.ss.mixHash(&e.public_key);
        self.ss.mixKey(&e.public_key);
        const ee = X25519.scalarmult(e.secret_key, self.re) catch return error.WeakPublicKey;
        self.ss.mixKey(&ee);
        try self.ss.encryptAndHash(out[key_len..len], payload);
        const cs = self.ss.split();
        return .{ .{ .send = cs[1], .recv = cs[0] }, out[0..len] };
    }
};

test "NKpsk0 handshake round trip" {
    const server = KeyPair.generate();
    const psk = pskFromSecret("hunter2");
    var ini = Initiator.init(server.public_key, psk, "test");
    var res = Responder.init(server, psk, "test");

    var m1: [128]u8 = undefined;
    var p1: [128]u8 = undefined;
    const msg1 = try ini.writeMessage1(&m1, "hello");
    try std.testing.expectEqualStrings("hello", try res.readMessage1(msg1, &p1));

    var m2: [128]u8 = undefined;
    var p2: [128]u8 = undefined;
    var rt, const msg2 = try res.writeMessage2(&m2, "world");
    var it, const pl = try ini.readMessage2(msg2, &p2);
    try std.testing.expectEqualStrings("world", pl);

    var ct: [5 + tag_len]u8 = undefined;
    var pt: [5]u8 = undefined;
    try it.send.encrypt(&ct, "", "abcde");
    try rt.recv.decrypt(&pt, "", &ct);
    try std.testing.expectEqualStrings("abcde", &pt);
    try rt.send.encrypt(&ct, "", "fghij");
    try it.recv.decrypt(&pt, "", &ct);
    try std.testing.expectEqualStrings("fghij", &pt);
}

test "NKpsk0 responder rejects wrong psk in message 1" {
    const server = KeyPair.generate();
    var ini = Initiator.init(server.public_key, pskFromSecret("a"), "");
    var res = Responder.init(server, pskFromSecret("b"), "");
    var m1: [64]u8 = undefined;
    var p1: [64]u8 = undefined;
    try std.testing.expectError(error.AuthenticationFailed, res.readMessage1(try ini.writeMessage1(&m1, ""), &p1));
}
