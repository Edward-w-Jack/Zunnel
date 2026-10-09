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

/// Loads a private key (base64) from `path`, creating a fresh one if missing.
pub fn loadOrCreate(path: []const u8) !struct { noise.KeyPair, bool } {
    var buf: [256]u8 = undefined;
    if (std.fs.cwd().readFile(path, &buf)) |contents| {
        const secret = decode(contents) catch return error.InvalidKeyFile;
        const public = try std.crypto.dh.X25519.recoverPublicKey(secret);
        return .{ .{ .secret_key = secret, .public_key = public }, false };
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    const kp = noise.KeyPair.generate();
    const text = encode(kp.secret_key);
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = &text ++ "\n" });
    return .{ kp, true };
}

test "key round trip" {
    const kp = noise.KeyPair.generate();
    try std.testing.expectEqual(kp.public_key, try decode(&encode(kp.public_key)));
}
