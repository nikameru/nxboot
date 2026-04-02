const std = @import("std");
const globals = @import("globals.zig");

pub fn buildRcmPayloadFromFile(rcm_payload_buf: []u8, payload_file: std.fs.File) !usize {
    std.mem.writeInt(u32, rcm_payload_buf[0..@sizeOf(u32)], @as(u32, globals.RCM_LENGTH), .little);

    var i: u32 = 0;
    const intermezzo_addr = globals.INTERMEZZO_ADDR;
    const intermezzo_addr_cnt: u32 = (intermezzo_addr - globals.RCM_PAYLOAD_ADDR) / @sizeOf(u32);

    while (i < intermezzo_addr_cnt) : (i += 1) {
        const idx = globals.HEADER_OFFSET + i * @sizeOf(u32);
        std.mem.writeInt(u32, rcm_payload_buf[idx..][0..@sizeOf(u32)], @as(u32, intermezzo_addr), .little);
    }

    const intermezzo_offset = globals.HEADER_OFFSET + intermezzo_addr - globals.RCM_PAYLOAD_ADDR;
    @memcpy(rcm_payload_buf[intermezzo_offset .. intermezzo_offset + globals.INTERMEZZO.len], &globals.INTERMEZZO);

    const payload_offset = intermezzo_offset + globals.PAYLOAD_LOAD_BLOCK - intermezzo_addr;
    const payload_file_size = try payload_file.getEndPos();
    const bytes_to_read = @min(payload_file_size, rcm_payload_buf.len - payload_offset);
    const bytes_read = try payload_file.readAll(rcm_payload_buf[payload_offset .. payload_offset + bytes_to_read]);

    const total_payload_size = payload_offset + bytes_read;
    if (total_payload_size == globals.RCM_LENGTH) {
        std.log.warn("warning: payload may have been truncated!", .{});
    }

    return total_payload_size;
}
