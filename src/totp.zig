const std = @import("std");
const otp = @import("otp.zig");

const MAX_HASH_SIZE = 32;

pub const Config = struct {
    interval: u32 = 30,
    digits: u8 = 6,
    algorithm: Algorithm = .sha1,
};

pub const URLConfig = struct {
    config: Config = .{},
    account: []const u8,
    issuer: ?[]const u8 = null,
};

pub const Algorithm = enum {
    sha1,
    sha256,
};

pub fn generate(buf: []u8, secret: []const u8, config: Config) ![]u8 {
    return generateAt(buf, secret, std.time.timestamp(), config);
}

pub fn generateAt(buf: []u8, secret: []const u8, timestamp: i64, config: Config) ![]u8 {
    std.debug.assert(buf.len >= config.digits);
    const code = generateCode(secret, timestamp, config);

    var writer = std.Io.Writer.fixed(buf);
    try writer.printInt(code, 10, .lower, .{ .fill = '0', .width = config.digits });
    return buf[0..writer.end];
}

pub fn verify(code: []const u8, secret: []const u8, config: Config) bool {
    return verifyAt(code, secret, std.time.timestamp(), config);
}

pub fn verifyAt(code: []const u8, secret: []const u8, timestamp: i64, config: Config) bool {
    if (code.len != config.digits) {
        return false;
    }
    std.debug.assert(code.len <= 10);
    return atoi(code) == generateCode(secret, timestamp, config);
}

pub fn bufUrl(buf: []u8, secret: []const u8, uc: URLConfig) ![]u8 {
    var fbs = std.io.fixedBufferStream(buf);
    url(fbs.writer().any(), secret, uc) catch |err| switch (err) {
        error.NoSpaceLeft => return error.NoSpaceLeft,
        else => unreachable,
    };
    return fbs.getWritten();
}

pub fn url(writer: anytype, secret: []const u8, uc: URLConfig) !void {
    try writer.writeAll("otpauth://totp/");
    if (uc.issuer) |is| {
        try encodeQueryComponent(writer, is);
        try writer.writeByte(':');
        try encodeQueryComponent(writer, uc.account);
        try writer.writeAll("?issuer=");
        try encodeQueryComponent(writer, is);
        try writer.writeByte('&');
    } else {
        try encodeQueryComponent(writer, uc.account);
        try writer.writeByte('?');
    }

    try writer.writeAll("secret=");
    try otp.encodeSecret(writer, secret);

    const config = uc.config;
    switch (config.algorithm) {
        .sha1 => try writer.writeAll("&algorithm=SHA1"),
        .sha256 => try writer.writeAll("&algorithm=SHA256"),
    }

    try std.fmt.format(writer, "&digits={d}", .{config.digits});
    try std.fmt.format(writer, "&interval={d}", .{config.interval});
}

fn generateCode(secret: []const u8, timestamp: i64, config: Config) u32 {
    var counter: [8]u8 = undefined;
    const timecode = @divTrunc(timestamp, config.interval);
    std.mem.writeInt(i64, &counter, timecode, .big);

    var buf: [MAX_HASH_SIZE]u8 = undefined;
    var hash: []u8 = undefined;
    switch (config.algorithm) {
        .sha1 => {
            var hasher = std.crypto.auth.hmac.HmacSha1.init(secret);
            hasher.update(&counter);
            hasher.final(buf[0..20]);
            hash = buf[0..20];
        },
        .sha256 => {
            var hasher = std.crypto.auth.hmac.sha2.HmacSha256.init(secret);
            hasher.update(&counter);
            hasher.final(buf[0..32]);
            hash = buf[0..32];
        },
    }

    const offset = hash[hash.len - 1] & 0x0f;
    const code: u32 = @as(u32, (hash[offset] & 0x7f)) << 24 | @as(u32, (hash[offset + 1] & 0xff)) << 16 | @as(u32, (hash[offset + 2] & 0xff)) << 8 | @as(u32, (hash[offset + 3] & 0xff));
    return @intCast(code % std.math.pow(u64, 10, @intCast(config.digits)));
}

fn atoi(str: []const u8) ?u32 {
    var n: u32 = 0;
    for (str) |b| {
        if (b < '0' or b > '9') {
            return null;
        }
        n = std.math.mul(u32, n, 10) catch return null;
        n = std.math.add(u32, n, @intCast(b - '0')) catch return null;
    }
    return n;
}

const UPPER_HEX = "0123456789ABCDEF";
fn encodeQueryComponent(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        if (shouldEscape(c)) {
            try writer.writeByte('%');
            try writer.writeByte(UPPER_HEX[c >> 4]);
            try writer.writeByte(UPPER_HEX[c & 15]);
        } else {
            try writer.writeByte(c);
        }
    }
}

fn shouldEscape(c: u8) bool {
    // fast path for common cases
    if (std.ascii.isAlphanumeric(c)) {
        return false;
    }
    return c != '-' and c != '_' and c != '.' and c != '~';
}

const expectEqual = std.testing.expectEqual;
const expectString = std.testing.expectEqualStrings;
test "TOTP: sha1" {
    var buf: [10]u8 = undefined;
    {
        const code = try generateAt(&buf, &.{ 69, 202, 138, 64, 98, 104, 96, 76, 8, 205, 202, 204, 34, 215, 20, 11, 93, 4, 253 }, 309776483, .{ .digits = 4 });
        try expectString("6286", code);
    }
    {
        const code = try generateAt(&buf, &.{ 123, 87, 102, 87, 55, 165 }, 1380925169, .{ .digits = 4 });
        try expectString("4873", code);
    }
    {
        const code = try generateAt(&buf, &.{ 95, 39, 9, 124, 69, 76, 0, 71, 17, 100, 184 }, 3660345236, .{ .digits = 4 });
        try expectString("8700", code);
    }
    {
        const code = try generateAt(&buf, &.{ 236, 129, 224, 0, 32, 71, 59, 42, 194, 161, 243 }, 6193291479, .{ .digits = 4 });
        try expectString("7855", code);
    }
    {
        const code = try generateAt(&buf, &.{ 248, 135, 204, 14, 204, 243, 181, 106, 27, 188, 139 }, 4611429756, .{ .digits = 5 });
        try expectString("41631", code);
    }
    {
        const code = try generateAt(&buf, &.{ 169, 168, 70, 228, 204, 82, 236 }, 117122720, .{ .digits = 4 });
        try expectString("9778", code);
    }
    {
        const code = try generateAt(&buf, &.{ 118, 182, 124 }, 7788307795, .{ .digits = 1 });
        try expectString("3", code);
    }
    {
        const code = try generateAt(&buf, &.{ 183, 158, 181, 235 }, 6347497068, .{ .digits = 4 });
        try expectString("6508", code);
    }
    {
        const code = try generateAt(&buf, &.{ 92, 133, 120, 44 }, 9081666226, .{ .digits = 1 });
        try expectString("4", code);
    }
    {
        const code = try generateAt(&buf, &.{ 174, 111, 31, 19, 56, 82, 3, 172, 12, 41, 142, 132, 169, 23, 240, 52, 214, 144 }, 5411807863, .{ .digits = 8 });
        try expectString("85867644", code);
    }
    {
        const code = try generateAt(&buf, &.{ 199, 36, 80, 24, 242, 201, 204, 19, 167, 94, 255, 40, 177, 183, 104, 33, 66, 189, 154 }, 8496686563, .{ .digits = 7 });
        try expectString("1067737", code);
    }
    {
        const code = try generateAt(&buf, &.{ 216, 35, 130, 95, 105, 94, 20, 119, 125, 187, 84, 134 }, 9911220343, .{ .digits = 4 });
        try expectString("0367", code);
    }
    {
        const code = try generateAt(&buf, &.{ 29, 250, 135, 29, 240, 170 }, 7215641219, .{ .digits = 10 });
        try expectString("0594144653", code);
    }
    {
        const code = try generateAt(&buf, &.{ 39, 28, 53, 44, 102, 166, 2, 128, 251, 75, 183, 78, 55, 100, 79, 118, 86 }, 5473838797, .{ .digits = 9 });
        try expectString("065836056", code);
    }
    {
        const code = try generateAt(&buf, &.{ 43, 188, 188, 123, 251, 88, 190, 207, 208, 249, 72, 36, 79, 78, 218, 229, 79, 32, 3 }, 1459566403, .{ .digits = 10 });
        try expectString("0810647789", code);
    }
    {
        const code = try generateAt(&buf, &.{ 64, 126, 55, 158, 97, 199, 118, 193, 2, 42 }, 4844719000, .{ .digits = 6 });
        try expectString("222916", code);
    }
    {
        const code = try generateAt(&buf, &.{ 183, 143, 77 }, 7312360664, .{ .digits = 3 });
        try expectString("366", code);
    }
    {
        const code = try generateAt(&buf, &.{ 106, 175 }, 5309528626, .{ .digits = 9 });
        try expectString("326804007", code);
    }
    {
        const code = try generateAt(&buf, &.{ 132, 166, 239, 219, 215, 34, 174, 207, 89, 94, 23 }, 7177560915, .{ .digits = 5 });
        try expectString("12479", code);
    }
    {
        const code = try generateAt(&buf, &.{ 46, 157, 4, 92, 112, 229, 247, 124, 66 }, 3660763143, .{ .digits = 8 });
        try expectString("12033779", code);
    }
    {
        const code = try generateAt(&buf, &.{ 232, 247, 11, 26, 143, 4, 96, 205 }, 4463513033, .{ .digits = 5 });
        try expectString("53305", code);
    }
    {
        const code = try generateAt(&buf, &.{187}, 5026689662, .{ .digits = 10 });
        try expectString("1205018998", code);
    }
    {
        const code = try generateAt(&buf, &.{ 147, 73, 53, 205, 157, 250, 40, 166, 61, 160, 237, 75, 17, 93, 231, 152, 67, 229 }, 7649841665, .{ .digits = 3 });
        try expectString("442", code);
    }
    {
        const code = try generateAt(&buf, &.{ 32, 47, 64, 159, 208, 229, 153, 121, 212, 4, 53, 134, 43, 144, 90, 72, 184 }, 7361431732, .{ .digits = 10 });
        try expectString("0222034431", code);
    }
    {
        const code = try generateAt(&buf, &.{ 88, 104, 234, 175, 3, 217 }, 3262336125, .{ .digits = 4 });
        try expectString("9987", code);
    }
    {
        const code = try generateAt(&buf, &.{ 138, 185, 56, 206 }, 4532776322, .{ .digits = 3 });
        try expectString("380", code);
    }
    {
        const code = try generateAt(&buf, &.{ 127, 83, 255, 120, 132, 97, 78 }, 8634253956, .{ .digits = 10 });
        try expectString("0281851516", code);
    }
    {
        const code = try generateAt(&buf, &.{ 161, 119, 28, 48, 115, 63, 138, 176, 204, 70, 99 }, 1519980245, .{ .digits = 4 });
        try expectString("6875", code);
    }
    {
        const code = try generateAt(&buf, &.{ 197, 234, 211, 203, 61, 188, 175, 74 }, 4974926740, .{ .digits = 5 });
        try expectString("43487", code);
    }
    {
        const code = try generateAt(&buf, &.{ 50, 64, 251, 254, 123, 112, 33, 232, 251, 241, 167, 93, 38 }, 6895021806, .{ .digits = 2 });
        try expectString("91", code);
    }
    {
        const code = try generateAt(&buf, &.{ 161, 64, 144, 199 }, 9477541979, .{ .digits = 2 });
        try expectString("72", code);
    }
    {
        const code = try generateAt(&buf, &.{ 238, 104 }, 1201798669, .{ .digits = 10 });
        try expectString("1602800943", code);
    }
    {
        const code = try generateAt(&buf, &.{ 174, 122, 159, 144, 138, 22, 188, 77, 199 }, 1147630261, .{ .digits = 5 });
        try expectString("29797", code);
    }
    {
        const code = try generateAt(&buf, &.{ 130, 16, 133, 126, 243, 12, 134, 0, 153, 184, 110, 147, 81, 70, 40 }, 6582460467, .{ .digits = 8 });
        try expectString("46693632", code);
    }
    {
        const code = try generateAt(&buf, &.{ 121, 254, 238, 41, 2, 215, 24, 172, 52, 198, 155, 29, 222, 237, 0, 235, 83, 227, 137, 48 }, 2994162672, .{ .digits = 8 });
        try expectString("30030214", code);
    }
    {
        const code = try generateAt(&buf, &.{ 243, 200, 71, 99, 51, 143, 202 }, 7311475515, .{ .digits = 1 });
        try expectString("3", code);
    }
    {
        const code = try generateAt(&buf, &.{ 73, 134, 100, 41, 234, 194, 51, 5, 166, 185, 215, 81, 56, 159, 181, 43, 18, 71, 186, 167 }, 2908689473, .{ .digits = 1 });
        try expectString("5", code);
    }
    {
        const code = try generateAt(&buf, &.{ 34, 25, 7, 242, 87, 60, 202, 115, 137, 136, 134, 29, 29, 13, 29, 107 }, 4133511736, .{ .digits = 3 });
        try expectString("221", code);
    }
    {
        const code = try generateAt(&buf, &.{254}, 2076036159, .{ .digits = 3 });
        try expectString("952", code);
    }
    {
        const code = try generateAt(&buf, &.{ 132, 205, 87, 150, 34, 55, 182, 50, 28, 239, 116, 175, 81, 11 }, 2201251310, .{ .digits = 4 });
        try expectString("8822", code);
    }
}

test "TOTP: sha256" {
    var buf: [10]u8 = undefined;
    {
        const code = try generateAt(&buf, &.{ 56, 161, 210, 54, 204, 109, 110, 67, 29, 111, 45, 99, 126, 224 }, 476281763, .{ .digits = 5, .algorithm = .sha256 });
        try expectString("48590", code);
    }
    {
        const code = try generateAt(&buf, &.{ 100, 41, 153, 241, 115, 92 }, 9038136576, .{ .digits = 8, .algorithm = .sha256 });
        try expectString("04752097", code);
    }
    {
        const code = try generateAt(&buf, &.{ 77, 173, 66, 254, 25, 162, 24, 98, 38, 68, 246, 227 }, 7857806342, .{ .digits = 5, .algorithm = .sha256 });
        try expectString("37751", code);
    }
    {
        const code = try generateAt(&buf, &.{ 132, 64, 27, 222, 172, 19, 58, 180, 155, 249, 161, 70, 211 }, 9915287973, .{ .digits = 10, .algorithm = .sha256 });
        try expectString("1322727074", code);
    }
    {
        const code = try generateAt(&buf, &.{ 124, 225, 224 }, 4678705079, .{ .digits = 1, .algorithm = .sha256 });
        try expectString("8", code);
    }
    {
        const code = try generateAt(&buf, &.{ 52, 137, 33, 165, 178, 235, 52, 44, 130, 246, 185, 114, 215, 114, 67, 145, 12, 125, 154, 99 }, 2269692885, .{ .digits = 5, .algorithm = .sha256 });
        try expectString("89778", code);
    }
    {
        const code = try generateAt(&buf, &.{ 234, 167, 144, 109, 149, 59, 23, 189, 211, 28, 168, 100, 168 }, 3730356627, .{ .digits = 10, .algorithm = .sha256 });
        try expectString("2118283183", code);
    }
    {
        const code = try generateAt(&buf, &.{ 140, 248, 228, 5, 65, 8, 47 }, 9319473115, .{ .digits = 4, .algorithm = .sha256 });
        try expectString("7347", code);
    }
    {
        const code = try generateAt(&buf, &.{ 22, 167, 138, 21, 175, 12 }, 1963135357, .{ .digits = 4, .algorithm = .sha256 });
        try expectString("9995", code);
    }
    {
        const code = try generateAt(&buf, &.{ 174, 140, 200, 222, 38, 214, 90 }, 3619219192, .{ .digits = 1, .algorithm = .sha256 });
        try expectString("1", code);
    }
    {
        const code = try generateAt(&buf, &.{ 17, 73, 173, 202, 250, 26, 235, 131, 158, 102, 217, 3 }, 9865602507, .{ .digits = 3, .algorithm = .sha256 });
        try expectString("328", code);
    }
    {
        const code = try generateAt(&buf, &.{ 138, 59, 24, 161, 189, 61, 173, 151, 231, 59, 247, 30, 19, 33, 198, 126, 90 }, 1003133834, .{ .digits = 8, .algorithm = .sha256 });
        try expectString("06752246", code);
    }
    {
        const code = try generateAt(&buf, &.{ 153, 205, 185, 187, 83, 150, 204, 240, 28, 201, 193, 66, 62, 45, 185, 241, 1, 239, 171, 154 }, 6270924767, .{ .digits = 10, .algorithm = .sha256 });
        try expectString("1533958442", code);
    }
    {
        const code = try generateAt(&buf, &.{ 15, 74, 15, 64, 178, 136, 152, 216, 253, 96, 32, 111 }, 6603280283, .{ .digits = 3, .algorithm = .sha256 });
        try expectString("463", code);
    }
    {
        const code = try generateAt(&buf, &.{123}, 3124565238, .{ .digits = 4, .algorithm = .sha256 });
        try expectString("5250", code);
    }
    {
        const code = try generateAt(&buf, &.{ 164, 121, 143, 159, 177, 136, 205 }, 9897349014, .{ .digits = 9, .algorithm = .sha256 });
        try expectString("403483860", code);
    }
    {
        const code = try generateAt(&buf, &.{ 19, 235, 5, 55, 242, 11, 105, 89, 132, 177, 173, 180 }, 4510407690, .{ .digits = 3, .algorithm = .sha256 });
        try expectString("974", code);
    }
    {
        const code = try generateAt(&buf, &.{ 43, 105, 207, 142, 103, 89, 53, 220, 20, 179, 158, 18, 103 }, 7013508728, .{ .digits = 6, .algorithm = .sha256 });
        try expectString("157304", code);
    }
    {
        const code = try generateAt(&buf, &.{ 231, 3, 201, 34, 79, 110, 199, 16, 2, 104, 225, 46, 229, 202 }, 2801526156, .{ .digits = 2, .algorithm = .sha256 });
        try expectString("14", code);
    }
    {
        const code = try generateAt(&buf, &.{ 46, 113, 239, 42, 65, 100, 211, 175, 195 }, 6723625740, .{ .digits = 5, .algorithm = .sha256 });
        try expectString("07082", code);
    }
    {
        const code = try generateAt(&buf, &.{ 13, 42, 72, 126, 199, 132, 8, 147, 14, 93, 141, 102 }, 6496503821, .{ .digits = 3, .algorithm = .sha256 });
        try expectString("748", code);
    }
    {
        const code = try generateAt(&buf, &.{ 105, 204, 70, 240, 133, 246, 26, 79, 239, 191 }, 1893215035, .{ .digits = 1, .algorithm = .sha256 });
        try expectString("8", code);
    }
    {
        const code = try generateAt(&buf, &.{ 180, 84 }, 4755255253, .{ .digits = 8, .algorithm = .sha256 });
        try expectString("31403626", code);
    }
    {
        const code = try generateAt(&buf, &.{ 93, 248, 133, 199, 196, 205, 126, 196, 251, 217, 29, 157, 140, 144, 157, 130 }, 8999336985, .{ .digits = 8, .algorithm = .sha256 });
        try expectString("05281172", code);
    }
    {
        const code = try generateAt(&buf, &.{ 22, 61, 162, 56, 76, 200, 184, 188, 17 }, 817665272, .{ .digits = 5, .algorithm = .sha256 });
        try expectString("33120", code);
    }
    {
        const code = try generateAt(&buf, &.{ 93, 73, 231, 191, 250, 190, 93 }, 5502625681, .{ .digits = 4, .algorithm = .sha256 });
        try expectString("1317", code);
    }
    {
        const code = try generateAt(&buf, &.{ 221, 247, 64, 194, 223, 182, 65 }, 9075764543, .{ .digits = 4, .algorithm = .sha256 });
        try expectString("9686", code);
    }
    {
        const code = try generateAt(&buf, &.{ 169, 1, 218 }, 7709263212, .{ .digits = 6, .algorithm = .sha256 });
        try expectString("555949", code);
    }
    {
        const code = try generateAt(&buf, &.{ 10, 90, 8, 148, 184, 41, 123, 30, 0, 74 }, 563428575, .{ .digits = 9, .algorithm = .sha256 });
        try expectString("783693985", code);
    }
    {
        const code = try generateAt(&buf, &.{ 21, 130, 32, 170, 223, 41, 3, 114, 39, 112 }, 9631711926, .{ .digits = 3, .algorithm = .sha256 });
        try expectString("306", code);
    }
    {
        const code = try generateAt(&buf, &.{ 196, 220, 202, 3, 254, 112, 21 }, 4174071548, .{ .digits = 9, .algorithm = .sha256 });
        try expectString("162003417", code);
    }
    {
        const code = try generateAt(&buf, &.{ 65, 121, 108, 195, 127, 29, 135, 118, 141, 169, 89, 192 }, 4641644436, .{ .digits = 2, .algorithm = .sha256 });
        try expectString("95", code);
    }
    {
        const code = try generateAt(&buf, &.{ 3, 246, 38 }, 7881552350, .{ .digits = 10, .algorithm = .sha256 });
        try expectString("0912114414", code);
    }
    {
        const code = try generateAt(&buf, &.{ 132, 109, 243, 226, 127, 227, 84, 199, 19, 117, 38, 167 }, 429438999, .{ .digits = 3, .algorithm = .sha256 });
        try expectString("762", code);
    }
    {
        const code = try generateAt(&buf, &.{ 24, 177, 34, 145, 203, 33, 48, 130, 253, 11, 49, 151 }, 1971684134, .{ .digits = 10, .algorithm = .sha256 });
        try expectString("0263175058", code);
    }
    {
        const code = try generateAt(&buf, &.{ 115, 133, 146, 8, 223 }, 9287078826, .{ .digits = 3, .algorithm = .sha256 });
        try expectString("594", code);
    }
    {
        const code = try generateAt(&buf, &.{ 236, 138, 181, 82, 122, 172, 175 }, 3193535761, .{ .digits = 3, .algorithm = .sha256 });
        try expectString("936", code);
    }
    {
        const code = try generateAt(&buf, &.{ 158, 68, 89, 182, 225, 20, 91, 15, 107, 208, 112, 80, 200, 132, 244, 228, 70 }, 1018808745, .{ .digits = 9, .algorithm = .sha256 });
        try expectString("033701787", code);
    }
    {
        const code = try generateAt(&buf, &.{ 12, 37, 211, 30, 69, 211 }, 3625784155, .{ .digits = 5, .algorithm = .sha256 });
        try expectString("57995", code);
    }
    {
        const code = try generateAt(&buf, &.{ 173, 244 }, 676073336, .{ .digits = 3, .algorithm = .sha256 });
        try expectString("271", code);
    }
}

test "TOTP: verifyAt" {
    try expectEqual(false, verifyAt("123", &.{}, 3, .{}));
    try expectEqual(false, verifyAt("123", &.{1}, 3, .{}));
    try expectEqual(false, verifyAt("123", &.{1}, 3, .{}));

    try expectEqual(true, verifyAt("4669617", &.{ 130, 170, 226, 17, 187, 241, 53, 237, 3 }, 5190221186, .{ .algorithm = .sha256, .digits = 7 }));
    try expectEqual(true, verifyAt("4669617", &.{ 130, 170, 226, 17, 187, 241, 53, 237, 3 }, 5190221187, .{ .algorithm = .sha256, .digits = 7 }));
    try expectEqual(false, verifyAt("4669618", &.{ 130, 170, 226, 17, 187, 241, 53, 237, 3 }, 5190221186, .{ .algorithm = .sha256, .digits = 7 }));
    try expectEqual(false, verifyAt("4669617", &.{ 130, 170, 226, 17, 187, 241, 53, 237, 3 }, 5190221186, .{ .algorithm = .sha1, .digits = 7 }));
    try expectEqual(false, verifyAt("4669617", &.{ 130, 170, 226, 17, 187, 241, 53, 237, 2 }, 5190221186, .{ .algorithm = .sha256, .digits = 7 }));
    try expectEqual(false, verifyAt("4669617", &.{ 130, 170, 226, 17, 187, 241, 53, 237, 3 }, 5190221186, .{ .algorithm = .sha256, .digits = 6 }));
    try expectEqual(false, verifyAt("4669617", &.{ 130, 170, 226, 17, 187, 241, 53, 237, 3 }, 5190221186, .{ .algorithm = .sha256, .digits = 8 }));
}

test "TOTP: fuzz" {
    var seed: u64 = undefined;
    std.posix.getrandom(std.mem.asBytes(&seed)) catch unreachable;
    var r = std.Random.DefaultPrng.init(seed);
    const random = r.random();

    var code_buf: [20]u8 = undefined;
    var secret_buf: [20]u8 = undefined;
    for (0..100) |_| {
        const secret_len = random.intRangeAtMost(usize, 4, 20);
        const secret = secret_buf[0..secret_len];
        otp.generateSecret(secret);

        var algorithm = Algorithm.sha1;
        if (random.intRangeAtMost(u8, 0, 1) == 1) {
            algorithm = .sha256;
        }

        const code_len = random.intRangeAtMost(usize, 4, 10);

        const timestamp = random.intRangeAtMost(i64, 9999999, 9999999999);
        const config = Config{
            .digits = @intCast(code_len),
            .algorithm = algorithm,
        };

        const code = try generateAt(&code_buf, secret, timestamp, config);
        try expectEqual(true, verifyAt(code, secret, timestamp, config));
    }
}

test "TOTP: url" {
    var buf: [200]u8 = undefined;
    {
        const u = try bufUrl(&buf, &.{ 1, 2, 3, 4, 5, 77, 7, 7, 4 }, .{ .account = "AC" });
        try expectString("otpauth://totp/AC?secret=AEBAGBAFJUDQOBA&algorithm=SHA1&digits=6&interval=30", u);
    }

    {
        const u = try bufUrl(&buf, &.{ 12, 34, 56 }, .{ .account = "!account!", .issuer = "an issuer", .config = .{ .digits = 10, .interval = 20, .algorithm = .sha256 } });
        try expectString("otpauth://totp/an%20issuer:%21account%21?issuer=an%20issuer&secret=BQRDQ&algorithm=SHA256&digits=10&interval=20", u);
    }

    {
        var arr: std.ArrayList(u8) = .empty;
        defer arr.deinit(std.testing.allocator);
        try url(arr.writer(std.testing.allocator), &.{ 12, 34, 56 }, .{ .account = "!account!", .issuer = "an issuer", .config = .{ .digits = 10, .interval = 20, .algorithm = .sha256 } });
        try expectString("otpauth://totp/an%20issuer:%21account%21?issuer=an%20issuer&secret=BQRDQ&algorithm=SHA256&digits=10&interval=20", arr.items);
    }
}
