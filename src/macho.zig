const std = @import("std");
pub const types = @import("types.zig");
pub usingnamespace types;

pub const ParseResult = struct {
    // Owns all memory for a single parse.
    allocator: std.mem.Allocator,
    file_size: u64,
    entities: std.ArrayList(types.Entity),
    diagnostics: std.ArrayList(types.Diagnostic),
    containments: std.ArrayList(types.Containment),
    fat_headers: std.ArrayList(types.FatHeader),
    fat_arch_entries: std.ArrayList(types.FatArchEntry),
    mach_headers: std.ArrayList(types.MachHeader),
    load_cmd_regions: std.ArrayList(types.LoadCommandsRegion),
    load_commands: std.ArrayList(types.LoadCommand),
    slice_entities: std.ArrayList(types.EntityId),

    pub fn init(allocator: std.mem.Allocator) ParseResult {
        return .{
            .allocator = allocator,
            .file_size = 0,
            .entities = std.ArrayList(types.Entity).init(allocator),
            .diagnostics = std.ArrayList(types.Diagnostic).init(allocator),
            .containments = std.ArrayList(types.Containment).init(allocator),
            .fat_headers = std.ArrayList(types.FatHeader).init(allocator),
            .fat_arch_entries = std.ArrayList(types.FatArchEntry).init(allocator),
            .mach_headers = std.ArrayList(types.MachHeader).init(allocator),
            .load_cmd_regions = std.ArrayList(types.LoadCommandsRegion).init(allocator),
            .load_commands = std.ArrayList(types.LoadCommand).init(allocator),
            .slice_entities = std.ArrayList(types.EntityId).init(allocator),
        };
    }

    pub fn deinit(self: *ParseResult) void {
        self.entities.deinit();
        self.diagnostics.deinit();
        self.containments.deinit();
        self.fat_headers.deinit();
        self.fat_arch_entries.deinit();
        self.mach_headers.deinit();
        self.load_cmd_regions.deinit();
        self.load_commands.deinit();
        self.slice_entities.deinit();
    }

    pub fn addEntity(self: *ParseResult, entity: types.Entity) !types.EntityId {
        const index: u32 = @intCast(self.entities.items.len);
        try self.entities.append(entity);
        return .{ .index = index };
    }

    pub fn addContainment(self: *ParseResult, kind: types.ContainmentKind, parent: types.EntityId, child: types.EntityId) !void {
        try self.containments.append(.{ .kind = kind, .parent = parent, .child = child });
    }

    pub fn addDiagnostic(self: *ParseResult, code: types.DiagnosticCode, severity: types.DiagnosticSeverity, range: types.ByteRange) !void {
        try self.diagnostics.append(.{
            .severity = severity,
            .code = code,
            .range = range,
        });
    }
};

pub fn parseFile(allocator: std.mem.Allocator, path: []const u8) !ParseResult {
    var file = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
    defer file.close();

    const stat = try file.stat();

    var result = ParseResult.init(allocator);
    result.file_size = stat.size;

    const file_id = try result.addEntity(.{
        .kind = types.EntityKind.File,
        .range = .{ .offset = 0, .size = stat.size },
    });

    // Stage: file classification by magic.
    if (stat.size < 4) {
        const size = @min(stat.size, @as(u64, 4));
        try result.addDiagnostic(.invalid_magic, .Error, .{ .offset = 0, .size = size });
        return result;
    }

    var magic_buf: [4]u8 = undefined;
    const magic_read = try file.preadAll(&magic_buf, 0);
    if (magic_read < magic_buf.len) {
        const size = @min(stat.size, @as(u64, 4));
        try result.addDiagnostic(.invalid_magic, .Error, .{ .offset = 0, .size = size });
        return result;
    }

    const magic_be = std.mem.readInt(u32, &magic_buf, .big);
    const magic = classifyMagic(magic_be);

    switch (magic.kind) {
        .fat => {
            try parseFat(&result, file, file_id, magic);
        },
        .thin => {
            const slice_id = try result.addEntity(.{
                .kind = types.EntityKind.Slice,
                .range = .{ .offset = 0, .size = stat.size },
            });
            try result.addContainment(.Owns, file_id, slice_id);
            try result.slice_entities.append(slice_id);
        },
        .unknown => {
            try result.addDiagnostic(.invalid_magic, .Error, .{ .offset = 0, .size = 4 });
        },
    }

    // Stage: slice header parsing and load command description.
    try parseSliceHeaders(&result, file);

    return result;
}

const MagicKind = enum(u8) {
    fat,
    thin,
    unknown,
};

const Magic = struct {
    kind: MagicKind,
    endian: types.Endianness,
    is_fat_64: bool,
};

fn parseFat(result: *ParseResult, file: std.fs.File, file_id: types.EntityId, magic: Magic) !void {
    const header_size: u64 = 8;
    if (result.file_size < header_size) {
        const size = @min(result.file_size, header_size);
        try result.addDiagnostic(.fat_header_truncated, .Error, .{ .offset = 0, .size = size });
        return;
    }

    const endian: std.builtin.Endian = if (magic.endian == .big) .big else .little;
    const nfat_arch = try readU32At(file, 4, endian);

    const header_id = try result.addEntity(.{
        .kind = types.EntityKind.FatHeader,
        .range = .{ .offset = 0, .size = header_size },
    });
    try result.addContainment(.Owns, file_id, header_id);

    try result.fat_headers.append(.{
        .magic = magicValue(magic),
        .nfat_arch = nfat_arch,
        .is_64 = if (magic.is_fat_64) 1 else 0,
        .endian = magic.endian,
        .entity = header_id,
    });

    const entry_size: u64 = if (magic.is_fat_64) 32 else 20;
    var i: u64 = 0;
    while (i < nfat_arch) : (i += 1) {
        const entry_offset = std.math.add(u64, header_size, std.math.mul(u64, i, entry_size) catch {
            try result.addDiagnostic(.fat_arch_truncated, .Error, .{ .offset = 0, .size = header_size });
            break;
        }) catch {
            try result.addDiagnostic(.fat_arch_truncated, .Error, .{ .offset = 0, .size = header_size });
            break;
        };
        const entry_end = std.math.add(u64, entry_offset, entry_size) catch {
            try result.addDiagnostic(.fat_arch_truncated, .Error, .{ .offset = entry_offset, .size = 0 });
            break;
        };
        if (entry_end > result.file_size) {
            const size = if (entry_offset >= result.file_size) 0 else result.file_size - entry_offset;
            try result.addDiagnostic(.fat_arch_truncated, .Error, .{ .offset = entry_offset, .size = size });
            break;
        }

        const entry_id = try result.addEntity(.{
            .kind = types.EntityKind.FatArchEntry,
            .range = .{ .offset = entry_offset, .size = entry_size },
        });
        try result.addContainment(.Owns, file_id, entry_id);

        const cputype = try readU32At(file, entry_offset + 0, endian);
        const cpusubtype = try readU32At(file, entry_offset + 4, endian);
        var offset: u64 = 0;
        var size: u64 = 0;
        var alignment: u32 = 0;
        var reserved: u32 = 0;

        if (magic.is_fat_64) {
            offset = try readU64At(file, entry_offset + 8, endian);
            size = try readU64At(file, entry_offset + 16, endian);
            alignment = try readU32At(file, entry_offset + 24, endian);
            reserved = try readU32At(file, entry_offset + 28, endian);
        } else {
            offset = @as(u64, try readU32At(file, entry_offset + 8, endian));
            size = @as(u64, try readU32At(file, entry_offset + 12, endian));
            alignment = try readU32At(file, entry_offset + 16, endian);
            reserved = 0;
        }

        const slice_id = try result.addEntity(.{
            .kind = types.EntityKind.Slice,
            .range = .{ .offset = offset, .size = size },
        });
        try result.addContainment(.Owns, file_id, slice_id);
        try result.slice_entities.append(slice_id);
        try result.addContainment(.Describes, entry_id, slice_id);

        try result.fat_arch_entries.append(.{
            .cputype = cputype,
            .cpusubtype = cpusubtype,
            .offset = offset,
            .size = size,
            .alignment = alignment,
            .reserved = reserved,
            .entity = entry_id,
            .slice = slice_id,
        });

        if (!rangeInBounds(result.file_size, offset, size)) {
            try result.addDiagnostic(.slice_out_of_bounds, .Error, .{ .offset = offset, .size = size });
        }
    }
}

fn parseSliceHeaders(result: *ParseResult, file: std.fs.File) !void {
    for (result.slice_entities.items) |slice_id| {
        const slice_entity = result.entities.items[@intCast(slice_id.index)];
        const slice_offset = slice_entity.range.offset;
        const slice_size = slice_entity.range.size;

        if (slice_size < 4) {
            const size = @min(slice_size, @as(u64, 4));
            try result.addDiagnostic(.mach_header_truncated, .Error, .{ .offset = slice_offset, .size = size });
            continue;
        }

        if (!rangeInBounds(result.file_size, slice_offset, 4)) {
            const remaining = if (slice_offset >= result.file_size) 0 else result.file_size - slice_offset;
            const size = @min(remaining, @as(u64, 4));
            try result.addDiagnostic(.mach_header_truncated, .Error, .{ .offset = slice_offset, .size = size });
            continue;
        }

        var magic_buf: [4]u8 = undefined;
        const read_len = try file.preadAll(&magic_buf, slice_offset);
        if (read_len < magic_buf.len) {
            try result.addDiagnostic(.mach_header_truncated, .Error, .{ .offset = slice_offset, .size = @as(u64, read_len) });
            continue;
        }

        const magic_be = std.mem.readInt(u32, &magic_buf, .big);
        const magic = classifyMachMagic(magic_be);
        if (magic.kind == .unknown) {
            try result.addDiagnostic(.invalid_mach_magic, .Error, .{ .offset = slice_offset, .size = 4 });
            continue;
        }

        const header_size: u64 = if (magic.is_64) 32 else 28;
        const header_end = std.math.add(u64, slice_offset, header_size) catch {
            try result.addDiagnostic(.mach_header_out_of_bounds, .Error, .{ .offset = slice_offset, .size = slice_size });
            continue;
        };

        if (header_size > slice_size) {
            try result.addDiagnostic(.mach_header_out_of_bounds, .Error, .{ .offset = slice_offset, .size = slice_size });
            continue;
        }

        if (header_end > result.file_size) {
            const remaining = if (slice_offset >= result.file_size) 0 else result.file_size - slice_offset;
            try result.addDiagnostic(.mach_header_truncated, .Error, .{ .offset = slice_offset, .size = remaining });
            continue;
        }

        const endian: std.builtin.Endian = if (magic.endian == .big) .big else .little;
        const cputype = try readU32At(file, slice_offset + 4, endian);
        const cpusubtype = try readU32At(file, slice_offset + 8, endian);
        const filetype = try readU32At(file, slice_offset + 12, endian);
        const ncmds = try readU32At(file, slice_offset + 16, endian);
        const sizeofcmds = try readU32At(file, slice_offset + 20, endian);
        const flags = try readU32At(file, slice_offset + 24, endian);
        const reserved = if (magic.is_64) try readU32At(file, slice_offset + 28, endian) else 0;

        const header_id = try result.addEntity(.{
            .kind = types.EntityKind.MachHeader,
            .range = .{ .offset = slice_offset, .size = header_size },
        });
        try result.addContainment(.Owns, slice_id, header_id);

        try result.mach_headers.append(.{
            .magic = magicValueMach(magic),
            .cputype = cputype,
            .cpusubtype = cpusubtype,
            .filetype = filetype,
            .ncmds = ncmds,
            .sizeofcmds = sizeofcmds,
            .flags = flags,
            .reserved = reserved,
            .is_64 = if (magic.is_64) 1 else 0,
            .endian = magic.endian,
            .entity = header_id,
        });

        try parseLoadCommands(result, file, slice_entity, header_id, header_size, ncmds, sizeofcmds, magic.endian);
    }
}

fn parseLoadCommands(
    result: *ParseResult,
    file: std.fs.File,
    slice_entity: types.Entity,
    header_id: types.EntityId,
    header_size: u64,
    ncmds: u32,
    sizeofcmds: u32,
    endian: types.Endianness,
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
        const header_bytes_end = std.math.add(u64, offset, 8) catch {
            try result.addDiagnostic(.load_cmd_header_truncated, .Error, .{ .offset = offset, .size = 0 });
            break;
        };
        if (header_bytes_end > region_end) {
            const size = if (offset >= region_end) 0 else region_end - offset;
            try result.addDiagnostic(.load_cmd_header_truncated, .Error, .{ .offset = offset, .size = size });
            break;
        }

        const cmd = try readU32At(file, offset + 0, cmd_endian);
        const cmdsize = try readU32At(file, offset + 4, cmd_endian);

        if (cmdsize < 8) {
            try result.addDiagnostic(.load_cmd_malformed_size, .Error, .{ .offset = offset, .size = cmdsize });
            break;
        }

        const cmd_end = std.math.add(u64, offset, cmdsize) catch {
            try result.addDiagnostic(.load_cmd_out_of_bounds, .Error, .{ .offset = offset, .size = cmdsize });
            break;
        };
        if (cmd_end > region_end) {
            try result.addDiagnostic(.load_cmd_out_of_bounds, .Error, .{ .offset = offset, .size = cmdsize });
            break;
        }

        const cmd_id = try result.addEntity(.{
            .kind = types.EntityKind.LoadCommand,
            .range = .{ .offset = offset, .size = cmdsize },
        });
        try result.addContainment(.Owns, region_id, cmd_id);
        try result.load_commands.append(.{ .cmd = cmd, .cmdsize = cmdsize, .entity = cmd_id });

        offset = cmd_end;
    }
}

fn readU32At(file: std.fs.File, offset: u64, endian: std.builtin.Endian) !u32 {
    var buf: [4]u8 = undefined;
    const read_len = try file.preadAll(&buf, offset);
    if (read_len < buf.len) return error.UnexpectedEof;
    return std.mem.readInt(u32, &buf, endian);
}

fn readU64At(file: std.fs.File, offset: u64, endian: std.builtin.Endian) !u64 {
    var buf: [8]u8 = undefined;
    const read_len = try file.preadAll(&buf, offset);
    if (read_len < buf.len) return error.UnexpectedEof;
    return std.mem.readInt(u64, &buf, endian);
}

fn rangeInBounds(file_size: u64, offset: u64, size: u64) bool {
    if (offset > file_size) return false;
    if (size > file_size) return false;
    const end = std.math.add(u64, offset, size) catch return false;
    return end <= file_size;
}

fn magicValue(magic: Magic) u32 {
    if (magic.kind != .fat) return 0;
    if (magic.is_fat_64) {
        return if (magic.endian == .big) 0xcafebabf else 0xbfbafeca;
    }
    return if (magic.endian == .big) 0xcafebabe else 0xbebafeca;
}

fn magicValueMach(magic: MachMagic) u32 {
    if (magic.kind != .thin) return 0;
    if (magic.is_64) {
        return if (magic.endian == .big) 0xfeedfacf else 0xcffaedfe;
    }
    return if (magic.endian == .big) 0xfeedface else 0xcefaedfe;
}

fn classifyMagic(magic_be: u32) Magic {
    return switch (magic_be) {
        0xcafebabe => .{ .kind = .fat, .endian = .big, .is_fat_64 = false },
        0xbebafeca => .{ .kind = .fat, .endian = .little, .is_fat_64 = false },
        0xcafebabf => .{ .kind = .fat, .endian = .big, .is_fat_64 = true },
        0xbfbafeca => .{ .kind = .fat, .endian = .little, .is_fat_64 = true },
        0xfeedface => .{ .kind = .thin, .endian = .big, .is_fat_64 = false },
        0xcefaedfe => .{ .kind = .thin, .endian = .little, .is_fat_64 = false },
        0xfeedfacf => .{ .kind = .thin, .endian = .big, .is_fat_64 = false },
        0xcffaedfe => .{ .kind = .thin, .endian = .little, .is_fat_64 = false },
        else => .{ .kind = .unknown, .endian = .big, .is_fat_64 = false },
    };
}

const MachMagic = struct {
    kind: MagicKind,
    endian: types.Endianness,
    is_64: bool,
};

fn classifyMachMagic(magic_be: u32) MachMagic {
    return switch (magic_be) {
        0xfeedface => .{ .kind = .thin, .endian = .big, .is_64 = false },
        0xcefaedfe => .{ .kind = .thin, .endian = .little, .is_64 = false },
        0xfeedfacf => .{ .kind = .thin, .endian = .big, .is_64 = true },
        0xcffaedfe => .{ .kind = .thin, .endian = .little, .is_64 = true },
        else => .{ .kind = .unknown, .endian = .big, .is_64 = false },
    };
}
