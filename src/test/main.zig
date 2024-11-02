const aegis = @cImport(@cInclude("aegis.h"));
const std = @import("std");
const random = std.crypto.random;
const testing = std.testing;

const max_msg_len: usize = 1000;
const max_ad_len: usize = 1000;
const iterations = 1000;

test "aegis128l" {
    var msg: [100]u8 = undefined;
    var c: [msg.len]u8 = undefined;
    var ad: [100]u8 = undefined;
    var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    var mac: [32]u8 = undefined;

    for (&msg, 0..) |*x, i| x.* = @truncate(i);
    for (&ad, 0..) |*x, i| x.* = @truncate(1 + i);
    for (&nonce, 0..) |*x, i| x.* = @truncate(2 + i);
    for (&key, 0..) |*x, i| x.* = @truncate(3 + i);

    const ret = aegis.aegis128l_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    const expected_mac = [_]u8{ 68, 221, 35, 187, 122, 131, 126, 255, 238, 44, 249, 194, 136, 73, 117, 112, 198, 131, 114, 252, 60, 9, 81, 217, 194, 52, 17, 239, 16, 79, 131, 118 };
    try testing.expectEqualSlices(u8, &mac, &expected_mac);
}

test "aegis128x2" {
    var msg: [100]u8 = undefined;
    var c: [msg.len]u8 = undefined;
    var ad: [100]u8 = undefined;
    var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    var mac: [32]u8 = undefined;

    for (&msg, 0..) |*x, i| x.* = @truncate(i);
    for (&ad, 0..) |*x, i| x.* = @truncate(1 + i);
    for (&nonce, 0..) |*x, i| x.* = @truncate(2 + i);
    for (&key, 0..) |*x, i| x.* = @truncate(3 + i);

    const ret = aegis.aegis128x2_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    const expected_mac = [_]u8{ 140, 181, 126, 87, 230, 79, 108, 196, 228, 190, 123, 241, 53, 252, 75, 11, 51, 194, 75, 237, 43, 1, 126, 233, 111, 187, 141, 239, 64, 112, 73, 105 };
    try testing.expectEqualSlices(u8, &mac, &expected_mac);
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
