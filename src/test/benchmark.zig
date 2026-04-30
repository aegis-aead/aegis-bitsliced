const aegis = @import("aegis");
const std = @import("std");
const Io = std.Io;
const mem = std.mem;
const time = std.time;

const msg_len: usize = 16384;
const iterations = 250000;

fn bench_aegis128l(io: Io) !void {
    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis128l_ABYTES_MIN]u8 = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);

    const start = Io.Clock.Timestamp.now(io, .awake);
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
    const end = Io.Clock.Timestamp.now(io, .awake);
    mem.doNotOptimizeAway(buf[0]);
    const elapsed_ns = start.durationTo(end).raw.nanoseconds;
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(elapsed_ns)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    std.debug.print("AEGIS-128L\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis256(io: Io) !void {
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis256_ABYTES_MIN]u8 = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);

    const start = Io.Clock.Timestamp.now(io, .awake);
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
    const end = Io.Clock.Timestamp.now(io, .awake);
    mem.doNotOptimizeAway(buf[0]);
    const elapsed_ns = start.durationTo(end).raw.nanoseconds;
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(elapsed_ns)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    std.debug.print("AEGIS-256\t{d:10.2} Mb/s\n", .{throughput});
}

fn bench_aegis128x2(io: Io) !void {
    var key: [aegis.aegis128x2_KEYBYTES]u8 = undefined;
    var nonce: [aegis.aegis128x2_NPUBBYTES]u8 = undefined;
    var buf: [msg_len + aegis.aegis128x2_ABYTES_MIN]u8 = undefined;

    io.random(&key);
    io.random(&nonce);
    io.random(&buf);

    const start = Io.Clock.Timestamp.now(io, .awake);
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
    const end = Io.Clock.Timestamp.now(io, .awake);
    mem.doNotOptimizeAway(buf[0]);
    const elapsed_ns = start.durationTo(end).raw.nanoseconds;
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(elapsed_ns)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000 * 1000)));
    std.debug.print("AEGIS-128X2\t{d:10.2} Mb/s\n", .{throughput});
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    try bench_aegis128l(io);
    try bench_aegis128x2(io);
    try bench_aegis256(io);
}
