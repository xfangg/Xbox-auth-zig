const std = @import("std");
const c = @cImport({
    @cInclude("curl/curl.h");
});

pub const AuthError = error{ CurlFailCreate, CurlFailSetOpt, CurlFailPerform, AwaitingAuth, Unexpected };

pub fn checkCode(code: c.CURLcode) !void {
    if (code != c.CURLE_OK) {
        std.debug.print("cURL Error code: {d}\n", .{code});
        return AuthError.CurlFailSetOpt;
    }
    return;
}
