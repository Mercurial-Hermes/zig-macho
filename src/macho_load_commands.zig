const std = @import("std");
const typed_cmds = @import("macho_typed_commands.zig");
const types = @import("types.zig");

// Stage: generic load command region parsing and range accounting.
pub fn parseLoadCommands(
    result: anytype,
    file: std.fs.File,
    slice_entity: types.Entity,
    slice_id: types.EntityId,
    header_id: types.EntityId,
    header_size: u64,
    ncmds: u32,
    sizeofcmds: u32,
    endian: types.Endianness,
    is_64: bool,
) !void {
    const header_end = std.math.add(u64, slice_entity.range.offset, header_size) catch {
        try result.addDiagnostic(.load_cmd_region_out_of_bounds, .Error, slice_entity.range);
        return;
    };
    const region_size = @as(u64, sizeofcmds);
    const region_end = std.math.add(u64, header_end, region_size) catch {
        try result.addDiagnostic(.load_cmd_region_out_of_bounds, .Error, slice_entity.range);
        return;
    };

    const region_id = try result.addEntity(.{
        .kind = types.EntityKind.LoadCommandsRegion,
        .range = .{ .offset = header_end, .size = region_size },
        .identity = .{ .index = 0 },
    });
    try result.addContainment(.Owns, header_id, region_id);
    try result.load_cmd_regions.append(.{ .sizeofcmds = sizeofcmds, .entity = region_id });

    const slice_end = std.math.add(u64, slice_entity.range.offset, slice_entity.range.size) catch {
        try result.addDiagnostic(.load_cmd_region_out_of_bounds, .Error, slice_entity.range);
        return;
    };

    if (region_end > slice_end) {
        try result.addDiagnostic(.load_cmd_region_out_of_bounds, .Error, .{ .offset = header_end, .size = region_size });
        return;
    }

    if (region_end > result.file_size) {
        const remaining = if (header_end >= result.file_size) 0 else result.file_size - header_end;
        try result.addDiagnostic(.load_cmd_region_truncated, .Error, .{ .offset = header_end, .size = remaining });
        return;
    }

    const cmd_endian: std.builtin.Endian = if (endian == .big) .big else .little;
    var offset: u64 = header_end;
    var i: u32 = 0;
    while (i < ncmds) : (i += 1) {
        const cmd_offset = offset;
        const header_bytes_end = std.math.add(u64, offset, 8) catch {
            try result.addDiagnostic(.load_cmd_header_truncated, .Error, .{ .offset = offset, .size = 0 });
            try emitRegionPadding(result, region_id, offset, region_end);
            return;
        };
        if (header_bytes_end > region_end) {
            const size = if (offset >= region_end) 0 else region_end - offset;
            try result.addDiagnostic(.load_cmd_header_truncated, .Error, .{ .offset = offset, .size = size });
            try emitRegionPadding(result, region_id, offset, region_end);
            return;
        }

        const cmd = try readU32At(file, offset + 0, cmd_endian);
        const cmdsize = try readU32At(file, offset + 4, cmd_endian);

        if (cmdsize < 8) {
            try result.addDiagnostic(.load_cmd_malformed_size, .Error, .{ .offset = offset, .size = cmdsize });
            try emitRegionPadding(result, region_id, offset, region_end);
            return;
        }

        const cmd_end = std.math.add(u64, offset, cmdsize) catch {
            try result.addDiagnostic(.load_cmd_out_of_bounds, .Error, .{ .offset = offset, .size = cmdsize });
            try emitRegionPadding(result, region_id, offset, region_end);
            return;
        };
        if (cmd_end > region_end) {
            try result.addDiagnostic(.load_cmd_out_of_bounds, .Error, .{ .offset = offset, .size = cmdsize });
            try emitRegionPadding(result, region_id, offset, region_end);
            return;
        }

        const cmd_id = try result.addEntity(.{
            .kind = types.EntityKind.LoadCommand,
            .range = .{ .offset = offset, .size = cmdsize },
            .identity = .{ .index = 0 },
        });
        try result.addContainment(.Owns, region_id, cmd_id);
        try result.load_commands.append(.{ .cmd = cmd, .cmdsize = cmdsize, .entity = cmd_id });

        const parsed = try typed_cmds.parseTypedLoadCommand(
            result,
            file,
            slice_entity,
            slice_id,
            cmd_id,
            cmd,
            cmd_offset,
            cmdsize,
            cmd_endian,
            is_64,
        );
        if (parsed.handled and parsed.consumed < cmdsize) {
            const pad_offset = cmd_offset + parsed.consumed;
            const pad_size = cmdsize - parsed.consumed;
            if (pad_size > 0) {
                const pad_id = try result.addEntity(.{
                    .kind = types.EntityKind.LoadCommandPadding,
                    .range = .{ .offset = pad_offset, .size = pad_size },
                    .identity = .{ .index = 0 },
                });
                try result.addContainment(.Owns, cmd_id, pad_id);
            }
        }

        offset = cmd_end;
    }

    if (offset < region_end) {
        try emitRegionPadding(result, region_id, offset, region_end);
    }
}

fn emitRegionPadding(result: anytype, region_id: types.EntityId, offset: u64, region_end: u64) !void {
    if (offset >= region_end) return;
    const size = region_end - offset;
    const pad_id = try result.addEntity(.{
        .kind = types.EntityKind.LoadCommandPadding,
        .range = .{ .offset = offset, .size = size },
        .identity = .{ .index = 0 },
    });
    try result.addContainment(.Owns, region_id, pad_id);
}

pub fn readU32At(file: std.fs.File, offset: u64, endian: std.builtin.Endian) !u32 {
    var buf: [4]u8 = undefined;
    const read_len = try file.preadAll(&buf, offset);
    if (read_len < buf.len) return error.UnexpectedEof;
    return std.mem.readInt(u32, &buf, endian);
}

pub fn readU64At(file: std.fs.File, offset: u64, endian: std.builtin.Endian) !u64 {
    var buf: [8]u8 = undefined;
    const read_len = try file.preadAll(&buf, offset);
    if (read_len < buf.len) return error.UnexpectedEof;
    return std.mem.readInt(u64, &buf, endian);
}

pub fn readBytesAt(file: std.fs.File, offset: u64, buf: []u8) !void {
    const read_len = try file.preadAll(buf, offset);
    if (read_len < buf.len) return error.UnexpectedEof;
}

pub fn rangeInBounds(file_size: u64, offset: u64, size: u64) bool {
    if (offset > file_size) return false;
    if (size > file_size) return false;
    const end = std.math.add(u64, offset, size) catch return false;
    return end <= file_size;
}
