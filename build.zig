const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });

    const lib_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    lib_mod.addIncludePath(b.path("src/include"));

    lib_mod.addCSourceFiles(.{
        .files = &.{
            "src/common.c",
            "src/aegis128l.c",
            "src/aegis128x2.c",
            "src/aegis128x2_64.c",
            "src/aegis256.c",
        },
    });

    const lib = b.addLibrary(.{
        .name = "aegis",
        .root_module = lib_mod,
        .linkage = .static,
    });
    b.installArtifact(lib);

    b.installDirectory(.{
        .install_dir = .header,
        .install_subdir = "",
        .source_dir = b.path("src/include"),
    });

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/test/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addIncludePath(b.path("src/include"));
    test_mod.linkLibrary(lib);

    const main_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_main_tests = b.addRunArtifact(main_tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);

    const bench_mod = b.createModule(.{
        .root_source_file = b.path("src/test/benchmark.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_mod.addIncludePath(b.path("src/include"));
    bench_mod.linkLibrary(lib);

    const benchmark = b.addExecutable(.{
        .name = "benchmark",
        .root_module = bench_mod,
    });
    b.installArtifact(benchmark);
}
