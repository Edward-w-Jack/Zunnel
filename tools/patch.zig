//! Build-time source patcher: `patch <in> <out> [<find> <replace>]...`
//! Every <find> must occur exactly once in <in>; anything else is an error so
//! that an lwIP upgrade can never silently drop one of our patches.
const std = @import("std");

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try std.process.argsAlloc(arena);
    if (args.len < 3 or (args.len - 3) % 2 != 0) {
        std.debug.print("usage: patch <in> <out> [<find> <replace>]...\n", .{});
        std.process.exit(2);
    }

    var src = try std.fs.cwd().readFileAlloc(arena, args[1], 16 * 1024 * 1024);
    var i: usize = 3;
    while (i < args.len) : (i += 2) {
        const find = args[i];
        const replace = args[i + 1];
        const count = std.mem.count(u8, src, find);
        if (count != 1) {
            std.debug.print("patch: expected exactly 1 occurrence of '{s}' in {s}, found {d}\n", .{ find, args[1], count });
            std.process.exit(1);
        }
        src = try std.mem.replaceOwned(u8, arena, src, find, replace);
    }

    try std.fs.cwd().writeFile(.{ .sub_path = args[2], .data = src });
}
