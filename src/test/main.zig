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
