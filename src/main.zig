const std = @import("std");
const builtin = @import("builtin");
const usb = @import("usb.zig");
const payload = @import("payload.zig");
const globals = @import("globals.zig");

pub const std_options: std.Options = .{
    .log_level = switch (builtin.mode) {
        .Debug => .debug,
        else => .info,
    },
};

pub fn main() !void {
    std.log.info("nxboot (Zig {s})", .{builtin.zig_version_string});

    var args_iter = std.process.args();
    if (!args_iter.skip()) {
        std.log.err("bad args!", .{});
        return;
    }
    const payload_path = args_iter.next();
    if (payload_path == null) {
        std.log.err(
            \\specify a payload file path! example:
            \\
            \\$ nxboot /path/to/payload.bin
            \\
        , .{});
        return;
    }

    const payload_file = std.fs.cwd().openFile(payload_path.?, .{}) catch |err| {
        std.log.err("reading target payload file failed: {}", .{err});
        return;
    };

    var usb_ctx: ?*usb.c.libusb_context = null;
    if (usb.c.libusb_init(&usb_ctx) != usb.c.LIBUSB_SUCCESS) {
        std.log.err("libusb init failed", .{});
        return;
    }
    defer if (usb_ctx != null) usb.c.libusb_exit(usb_ctx);

    const nx_dev_handle = usb.prepareNxDevice(usb_ctx.?) catch |err| {
        std.log.err(
            \\failed to prepare switch device: {}
            \\check usb connection!
        , .{err});
        return;
    };
    defer usb.closeNxDevice(nx_dev_handle);
    std.log.info("switch device opened successfully", .{});

    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const rcm_payload_buf = try allocator.alloc(u8, globals.RCM_LENGTH);
    defer allocator.free(rcm_payload_buf);
    @memset(rcm_payload_buf, 0);

    const payload_size = try payload.buildRcmPayloadFromFile(rcm_payload_buf, payload_file);

    var dev_id_buf: [globals.NX_DEVICE_ID_LEN]u8 = undefined;
    try usb.readNxDeviceId(nx_dev_handle, dev_id_buf[0..]);
    std.log.info("read device id: {s}", .{std.fmt.bytesToHex(dev_id_buf, .lower)});

    const write_count = try usb.writeBufferInPackets(nx_dev_handle, rcm_payload_buf, payload_size);
    std.log.debug("wrote {} times", .{write_count});

    if (write_count & 1 == 0) try usb.switchToHighBuffer(nx_dev_handle);
    std.log.info("wrote the rcm payload. triggering vulnerability...", .{});

    if (builtin.mode == .Debug) try writeResultPayloadToDebugFile(rcm_payload_buf, rcm_payload_buf.len);

    usb.triggerVulnerability(allocator, nx_dev_handle) catch |err| {
        if (err != usb.UsbError.FailedToPerformControlTransfer) return err;

        std.log.info("payload was run successfully!", .{});
        return;
    };

    std.log.err("failed to trigger vulnerability (control transfer succeeded)!", .{});
}

fn writeResultPayloadToDebugFile(buf: []const u8, payload_size: usize) !void {
    const file = try std.fs.cwd().createFile(globals.PAYLOAD_DEBUG_FILE_NAME, .{ .truncate = true });
    defer file.close();

    try file.writeAll(buf[0..payload_size]);
}
