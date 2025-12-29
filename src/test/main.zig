const aegis = @cImport(@cInclude("aegis.h"));
const std = @import("std");
const random = std.crypto.random;
const testing = std.testing;

const max_msg_len: usize = 1000;
const max_ad_len: usize = 1000;
const iterations = 1000;

test "aegis128l" {
    var msg: [100]u8 = undefined;
    var msg2: [msg.len]u8 = undefined;
    var c: [msg.len]u8 = undefined;
    var ad: [101]u8 = undefined;
    var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    var mac: [32]u8 = undefined;

    for (&msg, 0..) |*x, i| x.* = @truncate(i);
    for (&ad, 0..) |*x, i| x.* = @truncate(1 + i);
    for (&nonce, 0..) |*x, i| x.* = @truncate(2 + i);
    for (&key, 0..) |*x, i| x.* = @truncate(3 + i);

    var ret = aegis.aegis128l_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    const expected_mac = [_]u8{ 226, 153, 19, 17, 126, 4, 2, 204, 222, 116, 15, 137, 196, 121, 24, 10, 206, 245, 140, 15, 60, 203, 185, 170, 233, 3, 206, 26, 152, 244, 99, 172 };
    try testing.expectEqualSlices(u8, &mac, &expected_mac);
    ret = aegis.aegis128l_decrypt_detached(&msg2, &c, c.len, &mac, mac.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis128x2" {
    var msg: [100]u8 = undefined;
    var msg2: [msg.len]u8 = undefined;
    var c: [msg.len]u8 = undefined;
    var ad: [101]u8 = undefined;
    var nonce: [aegis.aegis128x2_NPUBBYTES]u8 = undefined;
    var key: [aegis.aegis128x2_KEYBYTES]u8 = undefined;
    var mac: [32]u8 = undefined;

    for (&msg, 0..) |*x, i| x.* = @truncate(i);
    for (&ad, 0..) |*x, i| x.* = @truncate(1 + i);
    for (&nonce, 0..) |*x, i| x.* = @truncate(2 + i);
    for (&key, 0..) |*x, i| x.* = @truncate(3 + i);

    var ret = aegis.aegis128x2_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    const expected_mac = [_]u8{ 36, 14, 49, 60, 126, 23, 20, 197, 179, 40, 135, 71, 4, 45, 59, 78, 87, 247, 78, 95, 23, 100, 2, 94, 1, 126, 28, 70, 225, 246, 97, 84 };
    try testing.expectEqualSlices(u8, &mac, &expected_mac);
    ret = aegis.aegis128x2_decrypt_detached(&msg2, &c, c.len, &mac, mac.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis256" {
    var msg: [100]u8 = undefined;
    var msg2: [msg.len]u8 = undefined;
    var c: [msg.len]u8 = undefined;
    var ad: [101]u8 = undefined;
    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    var mac: [32]u8 = undefined;

    for (&msg, 0..) |*x, i| x.* = @truncate(i);
    for (&ad, 0..) |*x, i| x.* = @truncate(1 + i);
    for (&nonce, 0..) |*x, i| x.* = @truncate(2 + i);
    for (&key, 0..) |*x, i| x.* = @truncate(3 + i);

    var ret = aegis.aegis256_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    const expected_mac = [_]u8{ 26, 53, 229, 162, 206, 238, 244, 85, 57, 235, 86, 87, 139, 124, 115, 125, 161, 124, 254, 79, 203, 177, 9, 126, 73, 78, 67, 139, 26, 255, 203, 235 };
    try testing.expectEqualSlices(u8, &mac, &expected_mac);
    ret = aegis.aegis256_decrypt_detached(&msg2, &c, c.len, &mac, mac.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis256x2" {
    var msg: [100]u8 = undefined;
    var msg2: [msg.len]u8 = undefined;
    var c: [msg.len]u8 = undefined;
    var ad: [101]u8 = undefined;
    var nonce: [aegis.aegis256x2_NPUBBYTES]u8 = undefined;
    var key: [aegis.aegis256x2_KEYBYTES]u8 = undefined;
    var mac: [32]u8 = undefined;

    for (&msg, 0..) |*x, i| x.* = @truncate(i);
    for (&ad, 0..) |*x, i| x.* = @truncate(1 + i);
    for (&nonce, 0..) |*x, i| x.* = @truncate(2 + i);
    for (&key, 0..) |*x, i| x.* = @truncate(3 + i);

    var ret = aegis.aegis256x2_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis256x2_decrypt_detached(&msg2, &c, c.len, &mac, mac.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &msg, &msg2);
}

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    return std.fmt.bytesToHex(hex, .lower);
}

test "aegis256x2 - test vector 1 (empty message)" {
    const key = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    const nonce = [_]u8{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f };
    const expected_tag128 = [_]u8{ 0x62, 0xcd, 0xba, 0xb0, 0x84, 0xc8, 0x3d, 0xac, 0xdb, 0x94, 0x5b, 0xb4, 0x46, 0xf0, 0x49, 0xc8 };
    const expected_tag256 = [_]u8{ 0x25, 0xd7, 0xe7, 0x99, 0xb4, 0x9a, 0x80, 0x35, 0x4c, 0x3f, 0x88, 0x1a, 0xc2, 0xf1, 0x02, 0x7f, 0x47, 0x1a, 0x5d, 0x29, 0x30, 0x52, 0xbd, 0x99, 0x97, 0xab, 0xd3, 0xae, 0x84, 0x01, 0x4b, 0xb7 };

    var tag128: [16]u8 = undefined;
    var tag256: [32]u8 = undefined;

    var ret = aegis.aegis256x2_encrypt_detached(null, &tag128, 16, null, 0, null, 0, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &expected_tag128, &tag128);

    ret = aegis.aegis256x2_encrypt_detached(null, &tag256, 32, null, 0, null, 0, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &expected_tag256, &tag256);
}

test "aegis256x2 - test vector 2" {
    const key = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    const nonce = [_]u8{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f };
    const ad = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04 };
    const msg = [_]u8{ 0x04, 0x05, 0x06, 0x07 } ** 30;
    const expected_ct = [_]u8{ 0x72, 0x12, 0x0c, 0x2e, 0xa8, 0x23, 0x61, 0x80, 0xd6, 0x78, 0x59, 0x00, 0x1f, 0x47, 0x29, 0x07, 0x7b, 0x70, 0x64, 0xc4, 0x14, 0x38, 0x4f, 0xe3, 0xa7, 0xb5, 0x2f, 0x15, 0x71, 0xf4, 0xf8, 0xa7, 0xd0, 0xf0, 0x1e, 0x18, 0xdb, 0x4f, 0x3b, 0xc0, 0xad, 0xb1, 0x50, 0x70, 0x2e, 0x5d, 0x14, 0x7a, 0x8d, 0x36, 0x52, 0x21, 0x32, 0x76, 0x1b, 0x99, 0x4c, 0x1b, 0xd3, 0x95, 0x58, 0x9e, 0x2c, 0xcf, 0x07, 0x90, 0xdf, 0xe2, 0xa3, 0xd1, 0x2d, 0x61, 0xcd, 0x66, 0x6b, 0x28, 0x59, 0x82, 0x77, 0x39, 0xdb, 0x40, 0x37, 0xdd, 0x31, 0x24, 0xc7, 0x84, 0x24, 0x45, 0x93, 0x76, 0xf6, 0xca, 0xc0, 0x8e, 0x1a, 0x72, 0x23, 0xa2, 0xa4, 0x3e, 0x39, 0x8c, 0xe6, 0x38, 0x5c, 0xd6, 0x54, 0xa1, 0x9f, 0x48, 0x1c, 0xba, 0x3b, 0x8f, 0x25, 0x91, 0x0b, 0x42 };
    const expected_tag128 = [_]u8{ 0x63, 0x5d, 0x39, 0x18, 0x28, 0x52, 0x0b, 0xf1, 0x51, 0x27, 0x63, 0xf0, 0xc8, 0xf5, 0xcd, 0xbd };
    const expected_tag256 = [_]u8{ 0xb5, 0x66, 0x8d, 0x33, 0x17, 0x15, 0x9e, 0x9c, 0xc5, 0xd4, 0x6e, 0x48, 0x03, 0xc3, 0xa7, 0x6a, 0xd6, 0x3b, 0xb4, 0x2b, 0x3f, 0x47, 0x95, 0x6d, 0x94, 0xf3, 0x0d, 0xb8, 0xcb, 0x36, 0x6a, 0xd7 };

    var ct: [msg.len]u8 = undefined;
    var tag128: [16]u8 = undefined;
    var tag256: [32]u8 = undefined;
    var dec_msg: [msg.len]u8 = undefined;

    var ret = aegis.aegis256x2_encrypt_detached(&ct, &tag128, 16, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &expected_ct, &ct);
    try testing.expectEqualSlices(u8, &expected_tag128, &tag128);

    ret = aegis.aegis256x2_encrypt_detached(&ct, &tag256, 32, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &expected_ct, &ct);
    try testing.expectEqualSlices(u8, &expected_tag256, &tag256);

    ret = aegis.aegis256x2_decrypt_detached(&dec_msg, &ct, ct.len, &tag256, 32, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &msg, &dec_msg);
}

test "aegis-128l - encrypt_detached oneshot" {
    inline for ([_]usize{ 16, 32 }) |mac_len| {
        var msg_buf: [max_msg_len]u8 = undefined;
        var msg2_buf: [msg_buf.len]u8 = undefined;
        var ad_buf: [max_ad_len]u8 = undefined;
        var c_buf: [msg_buf.len]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&msg_buf);
        random.bytes(&ad_buf);

        for (0..iterations) |_| {
            const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
            const msg = msg_buf[0..msg_len];
            var c = c_buf[0..msg_len];
            _ = &c;

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis128l_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
            _ = &msg2;
            ret = aegis.aegis128l_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);
            try testing.expectEqualSlices(u8, msg, msg2);
        }
    }
}

test "aegis-256 - encrypt_detached oneshot" {
    inline for ([_]usize{ 16, 32 }) |mac_len| {
        var msg_buf: [max_msg_len]u8 = undefined;
        var msg2_buf: [msg_buf.len]u8 = undefined;
        var ad_buf: [max_ad_len]u8 = undefined;
        var c_buf: [msg_buf.len]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&msg_buf);
        random.bytes(&ad_buf);

        for (0..iterations) |_| {
            const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
            const msg = msg_buf[0..msg_len];
            var c = c_buf[0..msg_len];
            _ = &c;

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis256_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
            _ = &msg2;
            ret = aegis.aegis256_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);
            try testing.expectEqualSlices(u8, msg, msg2);
        }
    }
}

test "aegis-128x2 - encrypt_detached oneshot" {
    inline for ([_]usize{ 16, 32 }) |mac_len| {
        var msg_buf: [max_msg_len]u8 = undefined;
        var msg2_buf: [msg_buf.len]u8 = undefined;
        var ad_buf: [max_ad_len]u8 = undefined;
        var c_buf: [msg_buf.len]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&msg_buf);
        random.bytes(&ad_buf);

        for (0..iterations) |_| {
            const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
            const msg = msg_buf[0..msg_len];
            var c = c_buf[0..msg_len];
            _ = &c;

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis128x2_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis128x2_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis128x2_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
            _ = &msg2;
            ret = aegis.aegis128x2_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);
            try testing.expectEqualSlices(u8, msg, msg2);
        }
    }
}

test "aegis-256x2 - encrypt_detached oneshot" {
    inline for ([_]usize{ 16, 32 }) |mac_len| {
        var msg_buf: [max_msg_len]u8 = undefined;
        var msg2_buf: [msg_buf.len]u8 = undefined;
        var ad_buf: [max_ad_len]u8 = undefined;
        var c_buf: [msg_buf.len]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&msg_buf);
        random.bytes(&ad_buf);

        for (0..iterations) |_| {
            const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
            const msg = msg_buf[0..msg_len];
            var c = c_buf[0..msg_len];
            _ = &c;

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis256x2_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis256x2_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis256x2_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
            _ = &msg2;
            ret = aegis.aegis256x2_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);
            try testing.expectEqualSlices(u8, msg, msg2);
        }
    }
}
