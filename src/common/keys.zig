//! Key encoding helpers (keys are shown to users as standard base64).
const std = @import("std");
const noise = @import("noise.zig");

const b64 = std.base64.standard;
pub const encoded_len = b64.Encoder.calcSize(noise.key_len);

pub fn encode(key: [noise.key_len]u8) [encoded_len]u8 {
    var out: [encoded_len]u8 = undefined;
    _ = b64.Encoder.encode(&out, &key);
    return out;
}

pub fn decode(text: []const u8) error{InvalidKey}![noise.key_len]u8 {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    const n = b64.Decoder.calcSizeForSlice(trimmed) catch return error.InvalidKey;
    if (n != noise.key_len) return error.InvalidKey;
    var out: [noise.key_len]u8 = undefined;
    b64.Decoder.decode(&out, trimmed) catch return error.InvalidKey;
    return out;
}

/// Length of a generated shared secret (URL-safe base64 of 24 random bytes,
/// so it pastes into any shell without quoting).
pub const secret_len = 32;

pub const ServerIdentity = struct {
    keypair: noise.KeyPair,
    /// Shared secret agents must present.
    secret: [secret_len]u8,
    /// The key file did not exist and was created.
    created: bool,
    /// An existing key file had no secret yet; one was generated and saved.
    added_secret: bool,
};

/// Loads the server's private key and shared secret from `path`:
///
///     <base64 private key>
///     secret=<32 chars>
///
/// Creates the file if it is missing, and appends a fresh secret to key-only
/// files written by older versions.
pub fn loadOrCreate(path: []const u8) !ServerIdentity {
    var buf: [512]u8 = undefined;
    if (std.fs.cwd().readFile(path, &buf)) |contents| {
        const parsed = try parseKeyFile(contents);
        const public = try std.crypto.dh.X25519.recoverPublicKey(parsed.private);
        const kp: noise.KeyPair = .{ .secret_key = parsed.private, .public_key = public };
        if (parsed.secret) |s| return .{ .keypair = kp, .secret = s, .created = false, .added_secret = false };
        const secret = randomSecret();
        try writeKeyFile(path, kp, secret);
        return .{ .keypair = kp, .secret = secret, .created = false, .added_secret = true };
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    const kp = noise.KeyPair.generate();
    const secret = randomSecret();
    try writeKeyFile(path, kp, secret);
    return .{ .keypair = kp, .secret = secret, .created = true, .added_secret = false };
}

fn randomSecret() [secret_len]u8 {
    var raw: [24]u8 = undefined;
    std.crypto.random.bytes(&raw);
    var out: [secret_len]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&out, &raw);
    return out;
}

fn writeKeyFile(path: []const u8, kp: noise.KeyPair, secret: [secret_len]u8) !void {
    const text = encode(kp.secret_key) ++ "\nsecret=" ++ secret ++ "\n";
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = text[0..] });
}

fn parseKeyFile(contents: []const u8) error{InvalidKeyFile}!struct { private: [noise.key_len]u8, secret: ?[secret_len]u8 } {
    var private: ?[noise.key_len]u8 = null;
    var secret: ?[secret_len]u8 = null;
    var lines = std.mem.tokenizeAny(u8, contents, "\r\n");
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        if (line.len == 0 or line[0] == '#') continue;
        if (std.mem.startsWith(u8, line, "secret=")) {
            const s = line["secret=".len..];
            if (s.len != secret_len) return error.InvalidKeyFile;
            secret = s[0..secret_len].*;
        } else if (private == null) {
            private = decode(line) catch return error.InvalidKeyFile;
        } else return error.InvalidKeyFile;
    }
    return .{ .private = private orelse return error.InvalidKeyFile, .secret = secret };
}

test "key round trip" {
    const kp = noise.KeyPair.generate();
    try std.testing.expectEqual(kp.public_key, try decode(&encode(kp.public_key)));
}

test "key file with and without a secret" {
    const kp = noise.KeyPair.generate();
    const old = encode(kp.secret_key) ++ "\n";
    const p1 = try parseKeyFile(old[0..]);
    try std.testing.expectEqual(kp.secret_key, p1.private);
    try std.testing.expect(p1.secret == null);

    const secret = randomSecret();
    const new = encode(kp.secret_key) ++ "\r\nsecret=" ++ secret ++ "\r\n";
    const p2 = try parseKeyFile(new[0..]);
    try std.testing.expectEqual(kp.secret_key, p2.private);
    try std.testing.expectEqualSlices(u8, &secret, &p2.secret.?);

    try std.testing.expectError(error.InvalidKeyFile, parseKeyFile("secret=short\n"));
    try std.testing.expectError(error.InvalidKeyFile, parseKeyFile(""));
}
