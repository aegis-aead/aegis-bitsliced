const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });

    const lib = b.addStaticLibrary(.{
        .name = "aegis",
        .target = target,
        .optimize = optimize,
        .strip = true,
    });

    lib.linkLibC();

    lib.addIncludePath(b.path("src/include"));

    const source_files = &.{
        "src/common.c",
        "src/aegis128l.c",
        "src/aegis128x2.c",
        "src/aegis256.c",
    };
    lib.addCSourceFiles(.{ .files = source_files });
    b.installArtifact(lib);

    b.installDirectory(.{
        .install_dir = .header,
        .install_subdir = "",
        .source_dir = b.path("src/include"),
    });

    const main_tests = b.addTest(.{
        .root_source_file = b.path("src/test/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    main_tests.addIncludePath(b.path("src/include"));
    main_tests.linkLibrary(lib);

    const run_main_tests = b.addRunArtifact(main_tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);

    const benchmark = b.addExecutable(.{
        .name = "benchmark",
        .root_source_file = b.path("src/test/benchmark.zig"),
        .target = target,
        .optimize = optimize,
    });
    benchmark.addIncludePath(b.path("src/include"));
    benchmark.linkLibrary(lib);
    b.installArtifact(benchmark);
}
