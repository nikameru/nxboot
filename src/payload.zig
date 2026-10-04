const std = @import("std");

const Io = std.Io;
const Allocator = std.mem.Allocator;

const NxAddr = u32;
const nx_addr_size = @sizeOf(NxAddr);

const intermezzo = [_]u8{
    0x44, 0x00, 0x9F, 0xE5, 0x01, 0x11, 0xA0, 0xE3,
    0x40, 0x20, 0x9F, 0xE5, 0x00, 0x20, 0x42, 0xE0,
    0x08, 0x00, 0x00, 0xEB, 0x01, 0x01, 0xA0, 0xE3,
    0x10, 0xFF, 0x2F, 0xE1, 0x00, 0x00, 0xA0, 0xE1,
    0x2C, 0x00, 0x9F, 0xE5, 0x2C, 0x10, 0x9F, 0xE5,
    0x02, 0x28, 0xA0, 0xE3, 0x01, 0x00, 0x00, 0xEB,
    0x20, 0x00, 0x9F, 0xE5, 0x10, 0xFF, 0x2F, 0xE1,
    0x04, 0x30, 0x90, 0xE4, 0x04, 0x30, 0x81, 0xE4,
    0x04, 0x20, 0x52, 0xE2, 0xFB, 0xFF, 0xFF, 0x1A,
    0x1E, 0xFF, 0x2F, 0xE1, 0x20, 0xF0, 0x01, 0x40,
    0x5C, 0xF0, 0x01, 0x40, 0x00, 0x00, 0x02, 0x40,
    0x00, 0x00, 0x01, 0x40,
};
const rcm_len = 0x30298;
const header_offset = 0x2A8;
const payload_load_block: NxAddr = 0x40020000;
const intermezzo_addr: NxAddr = 0x4001F000;
const rcm_payload_addr: NxAddr = 0x40010000;

pub fn buildFromFile(
    io: Io,
    allocator: Allocator,
    payload_file: Io.File,
) !struct { buf: []u8, size: usize } {
    const rcm_payload_buf = try allocator.alloc(u8, rcm_len);
    @memset(rcm_payload_buf, 0);

    std.mem.writeInt(
        NxAddr,
        rcm_payload_buf[0..nx_addr_size],
        @as(NxAddr, rcm_len),
        .little,
    );

    const intermezzo_addr_count = (intermezzo_addr - rcm_payload_addr) / nx_addr_size;
    for (0..intermezzo_addr_count) |i| {
        const idx = header_offset + i * nx_addr_size;
        std.mem.writeInt(
            NxAddr,
            rcm_payload_buf[idx..][0..nx_addr_size],
            @as(NxAddr, intermezzo_addr),
            .little,
        );
    }

    const intermezzo_offset = header_offset + intermezzo_addr - rcm_payload_addr;
    @memcpy(
        rcm_payload_buf[intermezzo_offset .. intermezzo_offset + intermezzo.len],
        &intermezzo,
    );

    const payload_offset = intermezzo_offset + payload_load_block - intermezzo_addr;
    const payload_file_size = try payload_file.length(io);
    const bytes_to_read = @min(payload_file_size, rcm_payload_buf.len - payload_offset);
    const bytes_read = try payload_file.readPositionalAll(
        io,
        rcm_payload_buf[payload_offset .. payload_offset + bytes_to_read],
        0,
    );

    const total_payload_size = payload_offset + bytes_read;
    if (total_payload_size == rcm_len) {
        std.log.warn("warning: payload may have been truncated!", .{});
    }

    return .{
        .buf = rcm_payload_buf,
        .size = total_payload_size,
    };
}
