const std = @import("std");

pub const vid: u16 = 0x0581;
pub const pid: u16 = 0x011D;

pub const packet_header = [_]u8{ 0xba, 0x70, 0x24, 0x00, 0x00, 0x00, 0x00 };
pub const on_off_cmd = [_]u8{ 0x77, 0x58, 0x01, 0x85, 0x01, 0x56 };

pub fn buildPacket() [64]u8 {
    var packet: [64]u8 = std.mem.zeroes([64]u8);
    @memcpy(packet[0..packet_header.len], &packet_header);
    @memcpy(packet[packet_header.len .. packet_header.len + on_off_cmd.len], &on_off_cmd);
    return packet;
}

pub fn buildHidWritePacket() [65]u8 {
    var packet: [65]u8 = std.mem.zeroes([65]u8);
    const hid_packet = buildPacket();
    @memcpy(packet[1..], &hid_packet);
    return packet;
}

pub fn buildLegacyPacket() [32]u8 {
    var packet: [32]u8 = std.mem.zeroes([32]u8);
    @memcpy(packet[0..on_off_cmd.len], &on_off_cmd);
    return packet;
}

pub fn buildLegacyHidWritePacket() [33]u8 {
    var packet: [33]u8 = std.mem.zeroes([33]u8);
    const legacy = buildLegacyPacket();
    @memcpy(packet[1..], &legacy);
    return packet;
}
