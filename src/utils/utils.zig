const std = @import("std");

pub const Buffer = std.ArrayList(u8);

pub fn bufferWriteCallback(ptr: [*c]c_char, size: c_uint, nmemb: c_uint, user_data: *anyopaque) callconv(.C) c_uint {
    const real_size = size * nmemb;
    var buffer: *Buffer = @alignCast(@ptrCast(user_data));
    var typed_data: [*]u8 = @ptrCast(ptr);
    buffer.appendSlice(typed_data[0..real_size]) catch return 0;
    return real_size;
}

pub fn fileExists(path: []const u8) !bool {
    _ = std.fs.cwd().statFile(path) catch |err| switch (err) {
        error.FileNotFound => {
            return false;
        },
        else => {
            return err;
        },
    };

    return true;
}
