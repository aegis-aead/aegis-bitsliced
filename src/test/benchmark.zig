const aegis = @cImport(@cInclude("aegis.h"));
const std = @import("std");
const mem = std.mem;
const random = std.crypto.random;
const time = std.time;
const Timer = std.time.Timer;

const msg_len: usize = 16384;
const iterations = 250000;

fn bench_aegis128l() !void {
    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis128l_ABYTES_MIN]u8 = undefined;

    random.bytes(&key);
    random.bytes(&nonce);
    random.bytes(&buf);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        _ = aegis.aegis128l_encrypt(
            &buf,
            aegis.aegis128l_ABYTES_MIN,
            &buf,
            msg_len,
            null,
            0,
            &nonce,
            &key,
        );
    }
    const end = timer.read();
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    const stdout = std.io.getStdOut().writer();
    try stdout.print("AEGIS-128L\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis256() !void {
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis256_ABYTES_MIN]u8 = undefined;

    random.bytes(&key);
    random.bytes(&nonce);
    random.bytes(&buf);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        _ = aegis.aegis256_encrypt(
            &buf,
            aegis.aegis256_ABYTES_MIN,
            &buf,
            msg_len,
            null,
            0,
            &nonce,
            &key,
        );
    }
    const end = timer.read();
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    const stdout = std.io.getStdOut().writer();
    try stdout.print("AEGIS-256\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis128x2() !void {
    var key: [aegis.aegis128x2_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis128x2_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis128x2_ABYTES_MIN]u8 = undefined;

    random.bytes(&key);
    random.bytes(&nonce);
    random.bytes(&buf);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        _ = aegis.aegis128x2_encrypt(
            &buf,
            aegis.aegis128x2_ABYTES_MIN,
            &buf,
            msg_len,
            null,
            0,
            &nonce,
            &key,
        );
    }
    const end = timer.read();
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    const stdout = std.io.getStdOut().writer();
    try stdout.print("AEGIS-128X2\t{d:10.2} Mb/s\n", .{throughput});
}

pub fn main() !void {
    try bench_aegis128l();
    try bench_aegis128x2();
    try bench_aegis256();
}
