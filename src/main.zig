const std = @import("std");
const builtin = @import("builtin");

const payload = @import("payload.zig");
const NxDevice = @import("NxDevice.zig");

const Io = std.Io;
const log = std.log;

pub const std_options: std.Options = .{
    .log_level = switch (builtin.mode) {
        .debug => .debug,
        else => .info,
    },
};

const payload_debug_file_path = "debug_payload.bin";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const args = init.minimal.args;

    log.info("nxboot (Zig {s})", .{builtin.zig_version_string});

    var args_iter = args.iterate();
    if (!args_iter.skip()) {
        return log.err("bad args!", .{});
    }
    const payload_path = args_iter.next();
    if (payload_path == null) {
        log.err("specify a payload file path!", .{});

        return log.info("example: $ nxboot /path/to/payload.bin", .{});
    }

    const payload_file = Io.Dir.cwd().openFile(io, payload_path.?, .{}) catch |err| {
        return log.err("reading target payload file failed: {}", .{err});
    };

    const nx_device = NxDevice.open() catch |err| {
        log.err("failed to open switch device: {}", .{err});

        return log.warn("check usb connection!", .{});
    };
    defer nx_device.close();

    log.info("switch device opened successfully", .{});

    const rcm_payload = try payload.buildFromFile(io, gpa, payload_file);
    defer gpa.free(rcm_payload.buf);

    if (builtin.mode == .debug) {
        const file = try Io.Dir.cwd().createFile(
            io,
            payload_debug_file_path,
            .{ .truncate = true },
        );
        defer file.close(io);

        try file.writePositionalAll(io, rcm_payload.buf[0..rcm_payload.size], 0);

        log.debug("wrote the rcm payload to {s}", .{payload_debug_file_path});
    }

    nx_device.inject(gpa, rcm_payload.buf[0..rcm_payload.size]) catch |err| {
        return log.err("failed to launch exploit: {}", .{err});
    };

    log.info("payload has been run successfully!", .{});
}
