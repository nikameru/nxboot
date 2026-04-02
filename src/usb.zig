const std = @import("std");
const globals = @import("globals.zig");

pub const c = @cImport({
    @cInclude("libusb.h");
});

pub const UsbError = error{ FailedToOpenDevice, FailedToConfigure, FailedToClaimInterface, FailedToReadDeviceId, FailedToWrite, FailedToPerformControlTransfer };

pub fn prepareNxDevice(ctx: *c.libusb_context) UsbError!*c.struct_libusb_device_handle {
    const handle = c.libusb_open_device_with_vid_pid(ctx, globals.NX_VENDOR_ID, globals.NX_PRODUCT_ID);

    if (handle == null) {
        return UsbError.FailedToOpenDevice;
    }
    errdefer c.libusb_close(handle);

    if (c.libusb_set_configuration(handle, 1) != c.LIBUSB_SUCCESS) {
        return UsbError.FailedToConfigure;
    }

    if (c.libusb_claim_interface(handle, globals.NX_USB_INTERFACE) != c.LIBUSB_SUCCESS) {
        return UsbError.FailedToClaimInterface;
    }

    return handle.?;
}

pub fn closeNxDevice(handle: *c.libusb_device_handle) void {
    _ = c.libusb_release_interface(handle, globals.NX_USB_INTERFACE);
    c.libusb_close(handle);
}

pub fn readNxDeviceId(handle: *c.libusb_device_handle, buf: []u8) !void {
    var bytes_transferred: c_int = 0;
    const endpoint: u8 = c.LIBUSB_ENDPOINT_IN | 1;

    const res = c.libusb_bulk_transfer(
        handle,
        endpoint,
        buf.ptr,
        @intCast(buf.len),
        &bytes_transferred,
        @intCast(globals.DEFAULT_USB_TIMEOUT_MS),
    );

    if (res != c.LIBUSB_SUCCESS or bytes_transferred != buf.len) {
        return UsbError.FailedToReadDeviceId;
    }
}

pub fn writeBufferInPackets(handle: *c.libusb_device_handle, buf: []const u8, payload_size: usize) UsbError!u8 {
    var total_bytes_sent: u32 = 0;
    var curr_bytes_sent: c_int = 0;
    var write_count: u8 = 0;

    const endpoint: u8 = c.LIBUSB_ENDPOINT_OUT | 1;
    const packet_size: usize = globals.USB_PACKET_SIZE;

    while (total_bytes_sent < payload_size) : (total_bytes_sent += @intCast(curr_bytes_sent)) {
        const bytes_to_send: usize = @min(buf.len - total_bytes_sent, packet_size);
        const result = c.libusb_bulk_transfer(
            handle,
            endpoint,
            @constCast(&buf[total_bytes_sent]),
            @intCast(bytes_to_send),
            &curr_bytes_sent,
            @intCast(globals.DEFAULT_USB_TIMEOUT_MS),
        );

        if (result != c.LIBUSB_SUCCESS) {
            return UsbError.FailedToWrite;
        }

        write_count += 1;
    }

    return write_count;
}

pub fn switchToHighBuffer(handle: *c.libusb_device_handle) !void {
    var buf = [_]u8{0} ** globals.USB_PACKET_SIZE;

    _ = try writeBufferInPackets(handle, &buf, buf.len);
}

pub fn triggerVulnerability(
    allocator: std.mem.Allocator,
    handle: *c.libusb_device_handle,
) !void {
    const buf = try allocator.alloc(u8, globals.CONTROL_TRANSFER_LENGTH);
    defer allocator.free(buf);
    @memset(buf, 0);

    const bm_req_type: u8 = c.LIBUSB_ENDPOINT_IN | c.LIBUSB_REQUEST_TYPE_STANDARD | c.LIBUSB_RECIPIENT_INTERFACE;
    const result = c.libusb_control_transfer(handle, bm_req_type, 0x00, 0x00, 0x00, buf.ptr, globals.CONTROL_TRANSFER_LENGTH, globals.DEFAULT_USB_TIMEOUT_MS);

    if (result < 0) {
        return UsbError.FailedToPerformControlTransfer;
    }
}
