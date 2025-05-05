const std = @import("std");
const live = @import("auth/live.zig");
const xbox = @import("auth/xbox.zig");

pub fn msa_code(uri: []const u8, user_code: []const u8) void {
    std.debug.print("Authenticate at {s} using the code {s}\n", .{ uri, user_code });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const path = "token.json";

    // get live token for xbox auth
    const liveToken = live.getToken(allocator, path, msa_code) catch |err| {
        std.debug.print("{any}", .{err});
        return;
    };
    defer liveToken.deinit();

    // save token
    try live.writeToken(allocator, liveToken.value, path);

    // get xbox auth token ( needed for xsts )
    const xboxToken = try xbox.requestToken(allocator, liveToken.value);
    defer xboxToken.deinit();

    // get wrapped token
    const wrapped = try xbox.requestXBLToken(allocator, xboxToken.value, "http://xboxlive.com");
    defer wrapped.deinit();

    // unwrap
    const xbl = wrapped.value;

    // format and defer free token use this in http requests
    const token = try std.fmt.allocPrint(allocator, "XBL3.0 x={s};{s}", .{ xbl.DisplayClaims.xui[0].uhs, xbl.Token });
    defer allocator.free(token);

    return;
}
