const std = @import("std");
const utils = @import("../utils/utils.zig");
const errors = @import("errors.zig").AuthError;
const checkCode = @import("errors.zig").checkCode;
const c = @cImport({
    @cInclude("curl/curl.h");
});

const setopt = c.curl_easy_setopt;

pub const DeviceCodeResponse = struct {
    user_code: []u8,
    device_code: []u8,
    verification_uri: []u8,
    interval: u32,
    expires_in: u32,
};

const DevicePollError = struct {
    @"error": ?[]u8 = null,
    error_description: ?[]u8 = null,
};

pub const DevicePollResponse = struct {
    user_id: []u8,
    token_type: []u8,
    scope: []u8,
    access_token: []u8,
    refresh_token: []u8,
    expires_in: u32,
};

pub fn getToken(allocator: std.mem.Allocator, path: []const u8, msa_callback: fn (uri: []const u8, code: []const u8) void) !std.json.Parsed(DevicePollResponse) {
    if (try utils.fileExists(path)) {
        var token = try readToken(allocator, path);
        token = try refreshToken(allocator, token.value);
        return token;
    } else {
        const wrapped = try startDeviceAuth(allocator);
        defer wrapped.deinit();

        const deviceCode = wrapped.value;
        msa_callback(deviceCode.verification_uri, deviceCode.user_code);

        while (true) {
            const poll = pollDeviceAuth(allocator, deviceCode.device_code) catch |err| switch (err) {
                errors.AwaitingAuth => {
                    std.time.sleep(std.time.ns_per_s * @as(u64, deviceCode.interval));
                    continue;
                },
                errors.Unexpected => {
                    std.debug.print("Failed auth cause encountered unexpected error.\n", .{});
                    return errors.Unexpected;
                },
                else => {
                    std.debug.print("{?}\n", .{err});
                    return errors.Unexpected;
                },
            };

            std.debug.print("Logged in.\n", .{});
            return poll;
        }

        // Fallback
        return errors.Unexpected;
    }
}

pub fn refreshToken(allocator: std.mem.Allocator, token: DevicePollResponse) !std.json.Parsed(DevicePollResponse) {
    var responseBody = utils.Buffer.init(allocator);
    defer responseBody.deinit();

    const curl = c.curl_easy_init() orelse return errors.CurlFailCreate;
    defer c.curl_easy_cleanup(curl);

    try checkCode(setopt(curl, c.CURLOPT_URL, "https://login.live.com/oauth20_token.srf"));

    const headers = c.curl_slist_append(null, "Content-Type: application/x-www-form-urlencoded");
    _ = c.curl_easy_setopt(curl, c.CURLOPT_HTTPHEADER, headers);
    defer c.curl_slist_free_all(headers);

    const body = try std.fmt.allocPrint(allocator, "client_id=0000000048183522&scope=service::user.auth.xboxlive.com::MBI_SSL&grant_type=refresh_token&refresh_token={s}", .{token.refresh_token});
    defer allocator.free(body);

    try checkCode(setopt(curl, c.CURLOPT_POSTFIELDSIZE, body.len));
    try checkCode(setopt(curl, c.CURLOPT_POSTFIELDS, body.ptr));

    try checkCode(setopt(curl, c.CURLOPT_WRITEDATA, &responseBody));
    try checkCode(setopt(curl, c.CURLOPT_WRITEFUNCTION, utils.bufferWriteCallback));

    const responseCode = c.curl_easy_perform(curl);
    if (responseCode != c.CURLE_OK) {
        std.debug.print("curl_easy_perform failed: {}\n", .{responseCode});
        return errors.CurlFailPerform;
    }

    const response = try std.json.parseFromSlice(DevicePollResponse, allocator, responseBody.items, .{});
    return response;
}

pub fn startDeviceAuth(allocator: std.mem.Allocator) !std.json.Parsed(DeviceCodeResponse) {
    var responseBody = utils.Buffer.init(allocator);
    defer responseBody.deinit();

    const curl = c.curl_easy_init() orelse return errors.CurlFailCreate;
    defer c.curl_easy_cleanup(curl);

    try checkCode(setopt(curl, c.CURLOPT_URL, "https://login.live.com/oauth20_connect.srf"));

    const headers = c.curl_slist_append(null, "Content-Type: application/x-www-form-urlencoded");
    try checkCode(setopt(curl, c.CURLOPT_HTTPHEADER, headers));
    defer c.curl_slist_free_all(headers);

    const body = "client_id=0000000048183522&scope=service::user.auth.xboxlive.com::MBI_SSL&response_type=device_code";

    try checkCode(setopt(curl, c.CURLOPT_POSTFIELDSIZE, body.len));
    try checkCode(setopt(curl, c.CURLOPT_POSTFIELDS, body));

    try checkCode(setopt(curl, c.CURLOPT_WRITEDATA, &responseBody));
    try checkCode(setopt(curl, c.CURLOPT_WRITEFUNCTION, utils.bufferWriteCallback));

    const responseCode = c.curl_easy_perform(curl);
    if (responseCode != c.CURLE_OK) {
        std.debug.print("curl_easy_perform failed: {}\n", .{responseCode});
    }

    const response = try std.json.parseFromSlice(DeviceCodeResponse, allocator, responseBody.items, .{});
    return response;
}

pub fn pollDeviceAuth(
    allocator: std.mem.Allocator,
    deviceCode: []u8,
) !std.json.Parsed(DevicePollResponse) {
    var responseBody = utils.Buffer.init(allocator);
    defer responseBody.deinit();

    const curl = c.curl_easy_init() orelse return errors.CurlFailCreate;
    try checkCode(setopt(curl, c.CURLOPT_URL, "https://login.live.com/oauth20_token.srf"));

    const headers = c.curl_slist_append(null, "Content-Type: application/x-www-form-urlencoded");
    _ = c.curl_easy_setopt(curl, c.CURLOPT_HTTPHEADER, headers);
    defer c.curl_slist_free_all(headers);

    const body = try std.fmt.allocPrint(allocator, "client_id=0000000048183522&grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={s}", .{deviceCode});
    defer allocator.free(body);

    try checkCode(setopt(curl, c.CURLOPT_POSTFIELDSIZE, body.len));
    try checkCode(setopt(curl, c.CURLOPT_POSTFIELDS, body.ptr));

    try checkCode(c.curl_easy_setopt(curl, c.CURLOPT_WRITEDATA, &responseBody));
    try checkCode(c.curl_easy_setopt(curl, c.CURLOPT_WRITEFUNCTION, utils.bufferWriteCallback));

    const res = c.curl_easy_perform(curl);
    if (res != c.CURLE_OK) {
        std.debug.print("curl_easy_perform failed: {}\n", .{res});
    }

    const pollError = try std.json.parseFromSlice(DevicePollError, allocator, responseBody.items, .{
        .ignore_unknown_fields = true,
    });
    defer pollError.deinit();

    if (pollError.value.@"error") |err| {
        if (std.mem.eql(u8, err, "authorization_pending")) {
            return errors.AwaitingAuth;
        } else {
            std.debug.print("Failed to authorize: {?s}\n", .{err});
            return errors.Unexpected;
        }
    }

    const response = try std.json.parseFromSlice(DevicePollResponse, allocator, responseBody.items, .{});
    return response;
}

pub fn writeToken(allocator: std.mem.Allocator, token: DevicePollResponse, output: []const u8) !void {
    var buf = utils.Buffer.init(allocator);
    defer buf.deinit();

    try std.json.stringify(token, .{}, buf.writer());
    const file = try std.fs.cwd().createFile(output, .{ .truncate = true });
    defer file.close();

    try file.writeAll(buf.items);
}

pub fn readToken(allocator: std.mem.Allocator, input: []const u8) !std.json.Parsed(DevicePollResponse) {
    const tokenBuf = try std.fs.cwd().readFileAlloc(allocator, input, 4096);
    defer allocator.free(tokenBuf);

    const token = try std.json.parseFromSlice(
        DevicePollResponse,
        allocator,
        tokenBuf,
        .{},
    );

    return token;
}
