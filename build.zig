const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "neewer-tray",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .win32_manifest = null,
    });

    switch (target.result.os.tag) {
        .windows => {
            exe.linkSystemLibrary("user32");
            exe.linkSystemLibrary("shell32");
            exe.linkSystemLibrary("gdi32");
            exe.linkSystemLibrary("setupapi");
            exe.linkLibC();
            exe.addWin32ResourceFile(.{ .file = b.path("src/icon.rc") });
            exe.subsystem = .Windows;
        },
        .linux => {
            exe.use_lld = false;
            exe.linkLibC();
            exe.root_module.linkSystemLibrary("gio-2.0", .{ .use_pkg_config = .force });
            exe.root_module.linkSystemLibrary("gobject-2.0", .{ .use_pkg_config = .force });
            exe.root_module.linkSystemLibrary("glib-2.0", .{ .use_pkg_config = .force });
            exe.root_module.linkSystemLibrary("hidapi-hidraw", .{ .use_pkg_config = .force });
        },
        else => {},
    }

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}

