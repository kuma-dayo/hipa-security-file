const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "hipa-secfile",
        .root_module = b.createModule(.{
            .root_source_file = null,
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    exe.root_module.addCSourceFiles(.{
        .files = &[_][]const u8{
            "src/hipa_secfile.c",
            "src/main.c",
        },
        .flags = &[_][]const u8{ "-std=c11", "-Wall", "-Wextra" },
    });
    exe.root_module.addIncludePath(b.path("src"));
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    if (b.args) |args| run.addArgs(args);
    const run_step = b.step("run", "Run the decryptor");
    run_step.dependOn(&run.step);
}
