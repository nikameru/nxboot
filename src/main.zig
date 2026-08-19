const std = @import("std");
const builtin = @import("builtin");

const payload = @import("payload.zig");
const NxDevice = @import("NxDevice.zig");

const log = std.log;

pub const std_options: std.Options = .{
    .log_level = switch (builtin.mode) {
        .Debug => .debug,
        else => .info,
    },
};

const payload_debug_file_path = "debug_payload.bin";

pub fn main() !void {
    log.info("nxboot (Zig {s})", .{builtin.zig_version_string});

    var args_iter = std.process.args();
    if (!args_iter.skip()) {
        log.err("bad args!", .{});
        return;
    }
    const payload_path = args_iter.next();
    if (payload_path == null) {
        return log.err(
            \\specify a payload file path! example:
            \\
            \\$ nxboot /path/to/payload.bin
            \\
        , .{});
    }

    const payload_file = std.fs.cwd().openFile(payload_path.?, .{}) catch |err| {
        return log.err("reading target payload file failed: {}", .{err});
    };

    const nx_device = NxDevice.open() catch |err| {
        return log.err(
            \\failed to open switch device: {}
            \\check usb connection!
        , .{err});
    };
    defer nx_device.close();

    log.info("switch device opened successfully", .{});

    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    const allocator = gpa.allocator();
    defer {
        const check = gpa.deinit();
        if (check == .leak) {
            log.warn("leaked!", .{});
        }
    }

    const rcm_payload = try payload.buildFromFile(allocator, payload_file);
    defer allocator.free(rcm_payload.buf);

    if (builtin.mode == .Debug) {
        const file = try std.fs.cwd().createFile(
            payload_debug_file_path,
            .{ .truncate = true },
        );
        defer file.close();

        try file.writeAll(rcm_payload.buf[0..rcm_payload.size]);

        log.debug("wrote the rcm payload to {s}", .{payload_debug_file_path});
    }

    nx_device.inject(allocator, rcm_payload.buf[0..rcm_payload.size]) catch |err| {
        return log.err("failed to launch exploit: {}", .{err});
    };

    log.info("payload has been run successfully!", .{});
}
