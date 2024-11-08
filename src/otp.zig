const std = @import("std");

pub const totp = @import("totp.zig");

pub fn generateSecret(into: []u8) void {
    std.crypto.random.bytes(into);
}

pub fn encodeSecretLen(n: usize) usize {
    // padding: return (n + 4) / 5 * 8
    return n / 5 * 8 + (n % 5 * 8 + 4) / 5;
}

pub fn encodeSecret(writer: anytype, src: []const u8) !void {
    var input = src;
    var buf: [8]u8 = undefined;
    while (input.len > 4) {
        try writer.writeAll(bufEncodeSecret(&buf, input[0..5]));
        input = input[5..];
    }
    if (input.len > 0) {
        try writer.writeAll(bufEncodeSecret(&buf, input));
    }
}

pub fn bufEncodeSecret(buf: []u8, src: []const u8) []u8 {
    const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".*;
    const out_len = encodeSecretLen(src.len);
    std.debug.assert(buf.len >= out_len);

    var idx: usize = 0;
    var out_idx: usize = 0;
    const n: usize = (src.len / 5) * 5;

    if (n % 5 == 0) {
        while (idx < n) : ({
            idx += 5;
            out_idx += 8;
        }) {
            const hi: u32 = std.mem.readInt(u32, src[idx..][0..4], .big);

            var shift: u5 = 31;
            inline for (0..6) |i| {
                shift -= 5;
                buf[out_idx + i] = BASE32[(hi >> shift + 1) & 0x1f];
            }

            const lo: u32 = hi << 8 | src[idx + 4];
            buf[out_idx + 6] = BASE32[(lo >> 5) & 0x1f];
            buf[out_idx + 7] = BASE32[(lo) & 0x1f];
        }
    }

    var remaining = src.len - idx;
    if (remaining == 0) {
        return buf[0..out_len];
    }

    var val: u32 = 0;
    if (remaining == 4) {
        val |= @as(u32, src[idx + 3]);
        buf[out_idx + 6] = BASE32[val << 3 & 0x1f];
        buf[out_idx + 5] = BASE32[val >> 2 & 0x1f];
        remaining -= 1;
    }
    if (remaining == 3) {
        val |= @as(u32, src[idx + 2]) << 8;
        buf[out_idx + 4] = BASE32[val >> 7 & 0x1f];
        remaining -= 1;
    }
    if (remaining == 2) {
        val |= @as(u32, src[idx + 1]) << 16;
        buf[out_idx + 3] = BASE32[val >> 12 & 0x1f];
        buf[out_idx + 2] = BASE32[val >> 17 & 0x1f];
        remaining -= 1;
    }
    if (remaining == 1) {
        val |= @as(u32, src[idx]) << 24;
        buf[out_idx + 1] = BASE32[val >> 22 & 0x1f];
        buf[out_idx + 0] = BASE32[val >> 27 & 0x1f];
        remaining -= 1;
    }

    // const pad_from: usize = ((src.len - idx) * 8 / 5) + 1 + out_idx;
    // for (buf[pad_from..out_len]) |*pad| {
    //     pad.* = '=';
    // }
    return buf[0..out_len];
}

const expectString = std.testing.expectEqualStrings;
test {
    std.testing.refAllDecls(@This());
}

test bufEncodeSecret {
    var buf: [40]u8 = undefined;
    try expectString("", bufEncodeSecret(&buf, &.{}));
    try expectString("FI", bufEncodeSecret(&buf, &.{42}));
    try expectString("DDLQ", bufEncodeSecret(&buf, &.{ 24, 215 }));
    try expectString("BCDXW", bufEncodeSecret(&buf, &.{ 8, 135, 123 }));
    try expectString("YE2SVUI", bufEncodeSecret(&buf, &.{ 193, 53, 42, 209 }));
    try expectString("YOM6YO2S", bufEncodeSecret(&buf, &.{ 195, 153, 236, 59, 82 }));
    try expectString("643TY3W32Q", bufEncodeSecret(&buf, &.{ 247, 55, 60, 110, 219, 212 }));
    try expectString("U6UNLVDUMPSQ", bufEncodeSecret(&buf, &.{ 167, 168, 213, 212, 116, 99, 229 }));
    try expectString("HAQZWJP6UYFIY", bufEncodeSecret(&buf, &.{ 56, 33, 155, 37, 254, 166, 10, 140 }));
    try expectString("SYHSGUCZFCYKCCQ", bufEncodeSecret(&buf, &.{ 150, 15, 35, 80, 89, 40, 176, 161, 10 }));
    try expectString("QIA7DB4FPZLES66O", bufEncodeSecret(&buf, &.{ 130, 1, 241, 135, 133, 126, 86, 73, 123, 206 }));
    try expectString("W45LY63O52FUOIQYZA", bufEncodeSecret(&buf, &.{ 183, 58, 188, 123, 110, 238, 139, 71, 34, 24, 200 }));
    try expectString("YRET6ATUZFNYYFSTDJUA", bufEncodeSecret(&buf, &.{ 196, 73, 63, 2, 116, 201, 91, 140, 22, 83, 26, 104 }));
    try expectString("4HXO4I4L3BJ7FPNGNIGMK", bufEncodeSecret(&buf, &.{ 225, 238, 238, 35, 139, 216, 83, 242, 189, 166, 106, 12, 197 }));
    try expectString("U4AXMHBGSRMZBZKXCAZIKVY", bufEncodeSecret(&buf, &.{ 167, 1, 118, 28, 38, 148, 89, 144, 229, 87, 16, 50, 133, 87 }));
    try expectString("YYV2KM66X2V5A34QUHFBCJ74", bufEncodeSecret(&buf, &.{ 198, 43, 165, 51, 222, 190, 171, 208, 111, 144, 161, 202, 17, 39, 252 }));
    try expectString("WL333OOXN6BWO2WHF67EFQQHJE", bufEncodeSecret(&buf, &.{ 178, 247, 189, 185, 215, 111, 131, 103, 106, 199, 47, 190, 66, 194, 7, 73 }));
    try expectString("OHQRFMFKEB23GMOHI3BRAR6ULF2Q", bufEncodeSecret(&buf, &.{ 113, 225, 18, 176, 170, 32, 117, 179, 49, 199, 70, 195, 16, 71, 212, 89, 117 }));
    try expectString("TFBVHLTBM7B3RTZ75JLHOTXEKIR3W", bufEncodeSecret(&buf, &.{ 153, 67, 83, 174, 97, 103, 195, 184, 207, 63, 234, 86, 119, 78, 228, 82, 35, 187 }));
    try expectString("IQYLUBZAN7C4GV2AKLJP2CCP44GBUZY", bufEncodeSecret(&buf, &.{ 68, 48, 186, 7, 32, 111, 197, 195, 87, 64, 82, 210, 253, 8, 79, 231, 12, 26, 103 }));
}

test encodeSecret {
    var seed: u64 = undefined;
    std.posix.getrandom(std.mem.asBytes(&seed)) catch unreachable;
    var r = std.Random.DefaultPrng.init(seed);
    const random = r.random();

    var buf: [100]u8 = undefined;
    var writer_buf: [100]u8 = undefined;
    var secret_buf: [40]u8 = undefined;
    for (0..100) |_| {
        const secret = secret_buf[0..random.intRangeAtMost(usize, 1, secret_buf.len)];
        random.bytes(secret);
        const encoded = bufEncodeSecret(&buf, secret);

        var fbs = std.io.fixedBufferStream(&writer_buf);
        try encodeSecret(fbs.writer().any(), secret);
        try expectString(fbs.getWritten(), encoded);
    }
}
