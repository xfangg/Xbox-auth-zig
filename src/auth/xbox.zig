const std = @import("std");
const utils = @import("../utils/utils.zig");
const errors = @import("errors.zig").AuthError;
const checkCode = @import("errors.zig").checkCode;
const live = @import("live.zig");
const c = @cImport({
    @cInclude("curl/curl.h");
});

const setopt = c.curl_easy_setopt;

pub const XboxTokenProperties = struct {
    AuthMethod: []const u8,
    SiteName: []const u8,
    RpsTicket: []const u8,
};

pub const XboxTokenRequest = struct {
    Properties: XboxTokenProperties,
    RelyingParty: []const u8,
    TokenType: []const u8,
};

pub const XboxTokenResponse = struct {
    IssueInstant: []u8,
    NotAfter: []u8,
    Token: []u8,
    DisplayClaims: struct {
        xui: []struct {
            gtg: ?[]u8 = null,
            xid: ?[]u8 = null,
            uhs: []u8,
        },
    },
};

pub const XSTSTokenProperties = struct {
    SandboxId: []const u8,
    UserTokens: [1][]u8,
};

pub const XSTSTokenRequest = struct {
    Properties: XSTSTokenProperties,
    RelyingParty: []const u8,
    TokenType: []const u8,
};

pub const XSTSTokenResponse = struct {
    IssueInstant: []u8,
    NotAfter: []u8,
    Token: []u8,
    DisplayClaims: struct {
        xui: []struct {
            uhs: []u8,
        },
    },
};

pub fn requestToken(allocator: std.mem.Allocator, liveToken: live.DevicePollResponse) !std.json.Parsed(XboxTokenResponse) {
    var responseBody = utils.Buffer.init(allocator);
    defer responseBody.deinit();

    const curl = c.curl_easy_init() orelse return errors.CurlFailCreate;
    defer c.curl_easy_cleanup(curl);

    try checkCode(setopt(curl, c.CURLOPT_URL, "https://user.auth.xboxlive.com/user/authenticate"));

    var headers = c.curl_slist_append(null, "Content-Type: application/json");
    headers = c.curl_slist_append(headers, "Accept: application/json");
    defer c.curl_slist_free_all(headers);

    try checkCode(setopt(curl, c.CURLOPT_HTTPHEADER, headers));

    const ticket = try std.fmt.allocPrint(allocator, "t={s}", .{liveToken.access_token});
    defer allocator.free(ticket);

    const request = XboxTokenRequest{
        .Properties = XboxTokenProperties{
            .AuthMethod = "RPS",
            .SiteName = "user.auth.xboxlive.com",
            .RpsTicket = ticket,
        },
        .RelyingParty = "http://auth.xboxlive.com",
        .TokenType = "JWT",
    };

    var body = utils.Buffer.init(allocator);
    defer body.deinit();

    try std.json.stringify(request, .{}, body.writer());

    try checkCode(setopt(curl, c.CURLOPT_POSTFIELDSIZE, body.items.len));
    try checkCode(setopt(curl, c.CURLOPT_POSTFIELDS, body.items.ptr));

    try checkCode(setopt(curl, c.CURLOPT_WRITEDATA, &responseBody));
    try checkCode(setopt(curl, c.CURLOPT_WRITEFUNCTION, utils.bufferWriteCallback));

    const res = c.curl_easy_perform(curl);
    if (res != c.CURLE_OK) {
        std.debug.print("curl_easy_perform failed: {}\n", .{res});
    }

    const response = try std.json.parseFromSlice(XboxTokenResponse, allocator, responseBody.items, .{});
    return response;
}

pub fn requestXBLToken(allocator: std.mem.Allocator, token: XboxTokenResponse, relyingParty: []const u8) !std.json.Parsed(XSTSTokenResponse) {
    var responseBody = utils.Buffer.init(allocator);
    defer responseBody.deinit();

    const curl = c.curl_easy_init() orelse return errors.CurlFailCreate;
    defer c.curl_easy_cleanup(curl);

    try checkCode(setopt(curl, c.CURLOPT_URL, "https://xsts.auth.xboxlive.com/xsts/authorize"));

    var headers = c.curl_slist_append(null, "Content-Type: application/json");
    headers = c.curl_slist_append(headers, "Accept: application/json");
    defer c.curl_slist_free_all(headers);

    try checkCode(setopt(curl, c.CURLOPT_HTTPHEADER, headers));

    const request = XSTSTokenRequest{
        .Properties = XSTSTokenProperties{
            .SandboxId = "RETAIL",
            .UserTokens = .{token.Token},
        },
        .RelyingParty = relyingParty,
        .TokenType = "JWT",
    };

    var body = utils.Buffer.init(allocator);
    defer body.deinit();

    try std.json.stringify(request, .{}, body.writer());

    try checkCode(setopt(curl, c.CURLOPT_POSTFIELDSIZE, body.items.len));
    try checkCode(setopt(curl, c.CURLOPT_POSTFIELDS, body.items.ptr));

    try checkCode(setopt(curl, c.CURLOPT_WRITEDATA, &responseBody));
    try checkCode(setopt(curl, c.CURLOPT_WRITEFUNCTION, utils.bufferWriteCallback));

    const res = c.curl_easy_perform(curl);
    if (res != c.CURLE_OK) {
        std.debug.print("curl_easy_perform failed: {}\n", .{res});
    }

    const response = try std.json.parseFromSlice(XSTSTokenResponse, allocator, responseBody.items, .{ .ignore_unknown_fields = true });
    return response;
}
