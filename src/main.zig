const builtin = @import("builtin");

pub fn main() !void {
    switch (builtin.os.tag) {
        .windows => {
            @import("windows.zig").run();
        },
        .linux => {
            try @import("linux.zig").run();
        },
        else => @compileError("Unsupported platform"),
    }
}
