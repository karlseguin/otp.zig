# OTP for Zig

Currently only supports TOTP with SHA1 or SHA256.

```zig
const std = @import("std");
const otp = @import("otp");

pub fn main() !void {
    // You would store secret in the DB with the user
    var secret: [20]u8 = undefined;
    otp.generateSecret(&secret);

    // base32 encode the secret
    // (for a 20-byte secret, you need a 32 byte buffer)
    var code_buf: [32]u8 = undefined;
    std.debug.print("{s}\n", .{otp.bufEncodeSecret(&code_buf, &secret)});

    // verify a user-supplied totp
    const user_topt = "123456";
    if (otp.totp.verify(user_topt, &secret, .{})) {
        std.debug.print("GOOD!\n", .{});
    }
}
```

## Install
1) Add otp.zig as a dependency in your `build.zig.zon`:

```bash
zig fetch --save git+https://github.com/karlseguin/otp.zig#master
```

2) In your `build.zig`, add the `otp` module as a dependency you your program:

```zig
const otp = b.dependency("otp", .{
    .target = target,
    .optimize = optimize,
});

// the executable from your call to b.addExecutable(...)
exe.root_module.addImport("otp", otp.module("otp"));
```

## Secrets
The first thing to do is to generate a secret:

```zig
var secret: [20]u8 = undefined;
otp.generateSecret(&secret);
```

You can pick any size, but 20 bytes, as above, is recommended. You should store the secret along with a user.

`generateSecret` fills the supplied slice with raw bytes. You can base32 encode the secret using:

```zig
// write the base32 encoded secret to the writer
try otp.encodeSecret(writer, secret);

// OR

// write the base32 encoded secret into "encoded_buf"
var encoded_buf: [32]u8 = undefined;
const encoded = otp.bufEncodeSecret(&encoded_buf, secret);
```

When using `bufEncodedSecret`, the supplied buffer *must* be large enough to hold the encoded value. You can use `const len = otp.encodeSecretLen(secret.len)` to get the required length.

### TOTP

#### Config
Passed to various totp functions:

* `interval: u32` - How long a code should be valid for in seconds. Defaults to 30
* `digits: u8` - Number of digits. Defaults to 6.
* `algorithm: otp.totp.Algorithm` - The hash algorithm to use. Defaults to `.sha1` (other supported value is `.sha256`)

#### otp.totp.generate(buf: []u8, secret: []const u8, config: Config) ![]u8
Generate a new TOTP code for the current time. `buf` must be at least `config.digits`. A slice of `buf[0..config.digits]` is returned.


#### otp.totp.generateAt(buf: []u8, secret: []const u8, timestamp: i64, config: Config) ![]u8
Generate a new TOTP code for the specified time. `buf` must be at least `config.digits`. A slice of `buf[0..config.digits]` is returned.

#### otp.totp.verify(code: []const u8, secret: []const u8, config: Config) bool
Verifies that the given code is valid for the current time.

#### otp.totp.verifyAt(code: []const u8, secret: []const u8, timestamp: i64, config: Config) bool
Verifies that the given code is valid for the given time.


#### Example
```zig
var code_buf: [6]u8 = undefined;
const code = otp.totp.generate(&code, &secret, .{});
std.debug.assert(otp.totp.verify(code, &secret, .{}) == true);
```

Which is a shorthand for:

```zig
var code_buf: [6]u8 = undefined;
const now = std.time.timestamp()
const config = otp.TOTP.Config{
    .digits = 6,
    .interval = 30,
    .algorithm = .sha1,
};
const code = try otp.totp.generateAt(&code, &secret, now, config);
std.debug.assert(otp.totp.verifyAt(code, &secret, now config) == true);
```

When generating a code, the buffer, `code_buf` above, must be at least `config.digits` long.

#### URL
You can generate a URL (which is what would be put in a QR code) using either the `url` or `bufUrl` functions. These functions take their own type of config object:

* `account: []const u8` - The account name. Required
* `issuer: ?[]const u8` - Optional issuer name. Defaults to `null`
* `config: Config` - The TOTP configuration. Default to `.{}`

##### bufUrl(buf: []u8, secret: []const u8, uc: URLConfig) ![]u8
Writes the URL into `buf`. Returns an error if `buf` isn't large enough. Returns the URL on success.

##### url(writer: anytype, secret: []const u8, uc: URLConfig) !void
Writes the URL using the writer. 

```zig
// min length of buf will largely depend on the account name, issuer name and length of secret.
var buf: [200]u8 = undefined;
const url = try bufUrl(&buf, secret, .{.account = "Leto", .issuer = "spice.gov", .config = .{.digits = 8} });
```
