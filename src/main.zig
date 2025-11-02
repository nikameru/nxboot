const std = @import("std");
const builtin = @import("builtin");
const constants = @import("constants.zig");

const c = @cImport({
    @cInclude("libusb-1.0/libusb.h");
});

const UsbError = error{ FailedToOpenDevice, FailedToConfigure, FailedToClaimInterface, FailedToReadDeviceId, FailedToWrite, FailedToPerformControlTransfer };

fn buildRcmPayload(stdout: *std.Io.Writer, rcm_payload_buf: []u8, payload_file: std.fs.File) !usize {
    const payload_file_size = try payload_file.getEndPos();

    std.mem.writeInt(u32, rcm_payload_buf[0..@sizeOf(u32)], constants.RCM_LENGTH, .little);

    var i: u32 = 0;
    const intermezzo_addr = constants.INTERMEZZO_ADDR;
    const intermezzo_addr_cnt: u32 = (intermezzo_addr - constants.RCM_PAYLOAD_ADDR) / @sizeOf(u32);

    while (i < intermezzo_addr_cnt) : (i += 1) {
        const idx = constants.HEADER_OFFSET + i * @sizeOf(u32);
        std.mem.writeInt(u32, rcm_payload_buf[idx..][0..@sizeOf(u32)], intermezzo_addr, .little);
    }

    const intermezzo_offset = constants.HEADER_OFFSET + intermezzo_addr - constants.RCM_PAYLOAD_ADDR;
    @memcpy(rcm_payload_buf[intermezzo_offset .. intermezzo_offset + constants.INTERMEZZO.len], &constants.INTERMEZZO);

    const payload_offset = intermezzo_offset + constants.PAYLOAD_LOAD_BLOCK - intermezzo_addr;
    const bytes_to_read = if (payload_file_size < (rcm_payload_buf.len - payload_offset)) payload_file_size else (rcm_payload_buf.len - payload_offset);
    const bytes_read = try payload_file.readAll(rcm_payload_buf[payload_offset .. payload_offset + bytes_to_read]);

    const total_payload_size = payload_offset + bytes_read;
    if (total_payload_size == constants.RCM_LENGTH) {
        try stdout.print("warning: payload may have been truncated!\n", .{});
    }

    return total_payload_size;
}

fn prepareNxDeviceUsb(ctx: *c.libusb_context) UsbError!*c.struct_libusb_device_handle {
    const handle = c.libusb_open_device_with_vid_pid(ctx, constants.NX_VENDOR_ID, constants.NX_PRODUCT_ID);

    if (handle == null) {
        return UsbError.FailedToOpenDevice;
    }
    errdefer c.libusb_close(handle);

    if (c.libusb_set_configuration(handle, 1) != c.LIBUSB_SUCCESS) {
        return UsbError.FailedToConfigure;
    }

    if (c.libusb_claim_interface(handle, constants.NX_USB_INTERFACE) != c.LIBUSB_SUCCESS) {
        return UsbError.FailedToClaimInterface;
    }

    return handle.?;
}

fn closeNxDeviceUsb(handle: *c.libusb_device_handle) void {
    _ = c.libusb_release_interface(handle, constants.NX_USB_INTERFACE);
    c.libusb_close(handle);
}

fn readNxDeviceId(handle: *c.libusb_device_handle, buf: []u8) !void {
    var bytes_transferred: c_int = 0;
    const endpoint: u8 = c.LIBUSB_ENDPOINT_IN | 1;

    const res = c.libusb_bulk_transfer(
        handle,
        endpoint,
        buf.ptr,
        @intCast(buf.len),
        &bytes_transferred,
        @intCast(constants.DEFAULT_USB_TIMEOUT_MS),
    );

    if (res != c.LIBUSB_SUCCESS or bytes_transferred != buf.len) {
        return UsbError.FailedToReadDeviceId;
    }
}

fn writeBufferInPackets(handle: *c.libusb_device_handle, buf: []const u8, payload_size: usize) !usize {
    var total_bytes_sent: usize = 0;
    var curr_bytes_sent: c_int = 0;

    const endpoint: u8 = c.LIBUSB_ENDPOINT_OUT | 1;
    const packet_size: usize = constants.USB_PACKET_SIZE;

    while (total_bytes_sent < payload_size) : (total_bytes_sent += @intCast(curr_bytes_sent)) {
        const to_send: usize = if ((buf.len - total_bytes_sent) < packet_size) (buf.len - total_bytes_sent) else packet_size;
        const result = c.libusb_bulk_transfer(
            handle,
            endpoint,
            @constCast(&buf[total_bytes_sent]),
            @intCast(to_send),
            &curr_bytes_sent,
            @intCast(constants.DEFAULT_USB_TIMEOUT_MS),
        );

        if (result != c.LIBUSB_SUCCESS) {
            return UsbError.FailedToWrite;
        }
    }

    return total_bytes_sent;
}

fn switchToHighBuffer(handle: *c.libusb_device_handle) !void {
    var buf = [_]u8{0} ** constants.USB_PACKET_SIZE;

    _ = try writeBufferInPackets(handle, &buf, buf.len);
}

fn triggerVulnerability(
    allocator: *const std.mem.Allocator,
    handle: *c.libusb_device_handle,
) !void {
    var buf = try allocator.alloc(u8, constants.CONTROL_TRANSFER_LENGTH);
    defer allocator.free(buf);
    @memset(buf, 0);

    const bm_req_type: u8 = c.LIBUSB_ENDPOINT_IN | c.LIBUSB_REQUEST_TYPE_STANDARD | c.LIBUSB_RECIPIENT_INTERFACE;
    const result = c.libusb_control_transfer(handle, bm_req_type, 0x00, 0x00, 0x00, buf.ptr, constants.CONTROL_TRANSFER_LENGTH, constants.DEFAULT_USB_TIMEOUT_MS);

    if (result < 0) {
        return UsbError.FailedToPerformControlTransfer;
    }
}

fn writeResultPayloadToDebugFile(buf: []u8, payload_size: usize) !void {
    const file = try std.fs.cwd().createFile(constants.PAYLOAD_DEBUG_FILE_NAME, .{ .truncate = true });
    defer file.close();

    try file.writeAll(buf[0..payload_size]);
}

pub fn main() !void {
    var stdout_buf: [512]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;
    defer stdout.flush() catch @panic("flush to stdout failed!\n");

    try stdout.print("nxboot (Zig {s})\n\n", .{builtin.zig_version_string});

    var args_iter = std.process.args();
    if (!args_iter.skip()) {
        return stdout.print("bad args\n", .{});
    }
    const payload_path = args_iter.next();
    if (payload_path == null) {
        return stdout.print(
            \\specify a payload file path!
            \\example: nxboot /path/to/payload.bin
            \\
        , .{});
    }

    const payload_file = std.fs.cwd().openFile(payload_path.?, .{}) catch |err| {
        return stdout.print("reading target payload file failed: {}\n", .{err});
    };

    var usb_ctx: ?*c.libusb_context = null;
    if (c.libusb_init(&usb_ctx) != c.LIBUSB_SUCCESS) {
        return stdout.print("libusb init failed\n", .{});
    }
    defer if (usb_ctx != null) c.libusb_exit(usb_ctx);

    const nx_dev_handle = prepareNxDeviceUsb(usb_ctx.?) catch |err| {
        return stdout.print(
            \\failed to prepare switch device: {}
            \\check usb connection!
            \\
        , .{err});
    };
    defer closeNxDeviceUsb(nx_dev_handle);
    try stdout.print("switch device opened successfully\n", .{});

    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const allocator = &gpa.allocator();
    defer _ = gpa.deinit();

    const rcm_payload_buf = try allocator.alloc(u8, constants.RCM_LENGTH);
    defer allocator.free(rcm_payload_buf);
    @memset(rcm_payload_buf, 0);

    const payload_size = try buildRcmPayload(stdout, rcm_payload_buf, payload_file);

    var dev_id_buf: [constants.NX_DEVICE_ID_LEN]u8 = undefined;
    try readNxDeviceId(nx_dev_handle, dev_id_buf[0..]);
    try stdout.print("read device id: {s}\n", .{std.fmt.bytesToHex(dev_id_buf, .lower)});

    const bytes_sent = try writeBufferInPackets(nx_dev_handle, rcm_payload_buf, payload_size);

    if ((bytes_sent / constants.USB_PACKET_SIZE) % 2 != 1) try switchToHighBuffer(nx_dev_handle);
    try stdout.print("wrote the rcm payload. triggering vulnerability...\n", .{});

    if (builtin.mode == .Debug) try writeResultPayloadToDebugFile(rcm_payload_buf, bytes_sent);

    triggerVulnerability(allocator, nx_dev_handle) catch |err| {
        if (err == UsbError.FailedToPerformControlTransfer) {
            try stdout.print("payload was run successfully!\n", .{});
        } else {
            return err;
        }
    };
}
