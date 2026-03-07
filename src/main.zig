const builtin = @import("builtin");

pub fn main() void {
    if (builtin.os.tag != .windows) {
        @compileError("The Zig app is Windows-only. Use cosmic-applet/ for Linux.");
    }

    @import("windows.zig").run();
}
