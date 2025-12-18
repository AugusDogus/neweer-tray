const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "neewer-tray",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .win32_manifest = null,
    });

    // Link Windows libraries
    exe.linkSystemLibrary("user32");
    exe.linkSystemLibrary("shell32");
    exe.linkSystemLibrary("gdi32");
    
    // Link libc for TLS support
    exe.linkLibC();
    
    // Add Windows resource file for icon
    exe.addWin32ResourceFile(.{ .file = b.path("src/icon.rc") });

    // Subsystem: windows (no console window)
    exe.subsystem = .Windows;

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}

