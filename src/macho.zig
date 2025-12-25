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
    segment64_commands: std.ArrayList(types.Segment64Command),
    section64_records: std.ArrayList(types.Section64),
    symtab_commands: std.ArrayList(types.SymtabCommand),
    dysymtab_commands: std.ArrayList(types.DysymtabCommand),
    uuid_commands: std.ArrayList(types.UuidCommand),
    build_version_commands: std.ArrayList(types.BuildVersionCommand),
    build_tool_versions: std.ArrayList(types.BuildToolVersion),
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
            .segment64_commands = std.ArrayList(types.Segment64Command).init(allocator),
            .section64_records = std.ArrayList(types.Section64).init(allocator),
            .symtab_commands = std.ArrayList(types.SymtabCommand).init(allocator),
            .dysymtab_commands = std.ArrayList(types.DysymtabCommand).init(allocator),
            .uuid_commands = std.ArrayList(types.UuidCommand).init(allocator),
            .build_version_commands = std.ArrayList(types.BuildVersionCommand).init(allocator),
            .build_tool_versions = std.ArrayList(types.BuildToolVersion).init(allocator),
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
        self.segment64_commands.deinit();
        self.section64_records.deinit();
        self.symtab_commands.deinit();
        self.dysymtab_commands.deinit();
        self.uuid_commands.deinit();
        self.build_version_commands.deinit();
        self.build_tool_versions.deinit();
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
        });
        try result.addContainment(.Owns, region_id, cmd_id);
        try result.load_commands.append(.{ .cmd = cmd, .cmdsize = cmdsize, .entity = cmd_id });

        const parsed = try parseTypedLoadCommand(result, file, cmd_id, cmd, cmd_offset, cmdsize, cmd_endian);
        if (parsed.handled and parsed.consumed < cmdsize) {
            const pad_offset = cmd_offset + parsed.consumed;
            const pad_size = cmdsize - parsed.consumed;
            if (pad_size > 0) {
                const pad_id = try result.addEntity(.{
                    .kind = types.EntityKind.LoadCommandPadding,
                    .range = .{ .offset = pad_offset, .size = pad_size },
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

const TypedParseResult = struct {
    handled: bool,
    consumed: u64,
};

fn parseTypedLoadCommand(
    result: *ParseResult,
    file: std.fs.File,
    cmd_id: types.EntityId,
    cmd: u32,
    cmd_offset: u64,
    cmdsize: u32,
    endian: std.builtin.Endian,
) !TypedParseResult {
    return switch (cmd) {
        0x19 => parseSegment64(result, file, cmd_id, cmd_offset, cmdsize, endian),
        0x2 => parseSymtab(result, file, cmd_id, cmd_offset, cmdsize, endian),
        0xb => parseDysymtab(result, file, cmd_id, cmd_offset, cmdsize, endian),
        0x1b => parseUuid(result, file, cmd_id, cmd_offset, cmdsize),
        0x32 => parseBuildVersion(result, file, cmd_id, cmd_offset, cmdsize, endian),
        else => .{ .handled = false, .consumed = 0 },
    };
}

fn parseSegment64(
    result: *ParseResult,
    file: std.fs.File,
    cmd_id: types.EntityId,
    cmd_offset: u64,
    cmdsize: u32,
    endian: std.builtin.Endian,
) !TypedParseResult {
    const fixed_size: u64 = 72;
    if (cmdsize < fixed_size) {
        try result.addDiagnostic(.load_cmd_typed_truncated, .Error, .{ .offset = cmd_offset, .size = cmdsize });
        return .{ .handled = true, .consumed = 0 };
    }

    var segname: [16]u8 = undefined;
    try readBytesAt(file, cmd_offset + 8, segname[0..]);

    const vmaddr = try readU64At(file, cmd_offset + 24, endian);
    const vmsize = try readU64At(file, cmd_offset + 32, endian);
    const fileoff = try readU64At(file, cmd_offset + 40, endian);
    const filesize = try readU64At(file, cmd_offset + 48, endian);
    const maxprot = try readU32At(file, cmd_offset + 56, endian);
    const initprot = try readU32At(file, cmd_offset + 60, endian);
    const nsects = try readU32At(file, cmd_offset + 64, endian);
    const flags = try readU32At(file, cmd_offset + 68, endian);

    const segment_id = try result.addEntity(.{
        .kind = types.EntityKind.Segment64Command,
        .range = .{ .offset = cmd_offset, .size = fixed_size },
    });
    try result.addContainment(.Owns, cmd_id, segment_id);

    try result.segment64_commands.append(.{
        .cmd = 0x19,
        .cmdsize = cmdsize,
        .segname = segname,
        .vmaddr = vmaddr,
        .vmsize = vmsize,
        .fileoff = fileoff,
        .filesize = filesize,
        .maxprot = maxprot,
        .initprot = initprot,
        .nsects = nsects,
        .flags = flags,
        .cmd_range = .{ .offset = cmd_offset + 0, .size = 4 },
        .cmdsize_range = .{ .offset = cmd_offset + 4, .size = 4 },
        .segname_range = .{ .offset = cmd_offset + 8, .size = 16 },
        .vmaddr_range = .{ .offset = cmd_offset + 24, .size = 8 },
        .vmsize_range = .{ .offset = cmd_offset + 32, .size = 8 },
        .fileoff_range = .{ .offset = cmd_offset + 40, .size = 8 },
        .filesize_range = .{ .offset = cmd_offset + 48, .size = 8 },
        .maxprot_range = .{ .offset = cmd_offset + 56, .size = 4 },
        .initprot_range = .{ .offset = cmd_offset + 60, .size = 4 },
        .nsects_range = .{ .offset = cmd_offset + 64, .size = 4 },
        .flags_range = .{ .offset = cmd_offset + 68, .size = 4 },
        .entity = segment_id,
    });

    const sections_offset = cmd_offset + fixed_size;
    const available = @as(u64, cmdsize) - fixed_size;
    const section_size: u64 = 80;
    const max_sections = available / section_size;
    const parse_count: u64 = @min(@as(u64, nsects), max_sections);

    if (@as(u64, nsects) > max_sections) {
        try result.addDiagnostic(.load_cmd_sections_truncated, .Error, .{ .offset = sections_offset, .size = available });
    }

    var i: u64 = 0;
    while (i < parse_count) : (i += 1) {
        const sect_offset = sections_offset + i * section_size;
        var sectname: [16]u8 = undefined;
        var segname2: [16]u8 = undefined;
        try readBytesAt(file, sect_offset + 0, sectname[0..]);
        try readBytesAt(file, sect_offset + 16, segname2[0..]);
        const addr = try readU64At(file, sect_offset + 32, endian);
        const size = try readU64At(file, sect_offset + 40, endian);
        const offset_field = try readU32At(file, sect_offset + 48, endian);
        const alignment = try readU32At(file, sect_offset + 52, endian);
        const reloff = try readU32At(file, sect_offset + 56, endian);
        const nreloc = try readU32At(file, sect_offset + 60, endian);
        const flags_field = try readU32At(file, sect_offset + 64, endian);
        const reserved1 = try readU32At(file, sect_offset + 68, endian);
        const reserved2 = try readU32At(file, sect_offset + 72, endian);
        const reserved3 = try readU32At(file, sect_offset + 76, endian);

        const section_id = try result.addEntity(.{
            .kind = types.EntityKind.Section64,
            .range = .{ .offset = sect_offset, .size = section_size },
        });
        try result.addContainment(.Owns, segment_id, section_id);

        try result.section64_records.append(.{
            .sectname = sectname,
            .segname = segname2,
            .addr = addr,
            .size = size,
            .offset = offset_field,
            .alignment = alignment,
            .reloff = reloff,
            .nreloc = nreloc,
            .flags = flags_field,
            .reserved1 = reserved1,
            .reserved2 = reserved2,
            .reserved3 = reserved3,
            .sectname_range = .{ .offset = sect_offset + 0, .size = 16 },
            .segname_range = .{ .offset = sect_offset + 16, .size = 16 },
            .addr_range = .{ .offset = sect_offset + 32, .size = 8 },
            .size_range = .{ .offset = sect_offset + 40, .size = 8 },
            .offset_range = .{ .offset = sect_offset + 48, .size = 4 },
            .alignment_range = .{ .offset = sect_offset + 52, .size = 4 },
            .reloff_range = .{ .offset = sect_offset + 56, .size = 4 },
            .nreloc_range = .{ .offset = sect_offset + 60, .size = 4 },
            .flags_range = .{ .offset = sect_offset + 64, .size = 4 },
            .reserved1_range = .{ .offset = sect_offset + 68, .size = 4 },
            .reserved2_range = .{ .offset = sect_offset + 72, .size = 4 },
            .reserved3_range = .{ .offset = sect_offset + 76, .size = 4 },
            .entity = section_id,
        });
    }

    const consumed = fixed_size + parse_count * section_size;
    return .{ .handled = true, .consumed = consumed };
}

fn parseSymtab(
    result: *ParseResult,
    file: std.fs.File,
    cmd_id: types.EntityId,
    cmd_offset: u64,
    cmdsize: u32,
    endian: std.builtin.Endian,
) !TypedParseResult {
    const fixed_size: u64 = 24;
    if (cmdsize < fixed_size) {
        try result.addDiagnostic(.load_cmd_typed_truncated, .Error, .{ .offset = cmd_offset, .size = cmdsize });
        return .{ .handled = true, .consumed = 0 };
    }

    const symoff = try readU32At(file, cmd_offset + 8, endian);
    const nsyms = try readU32At(file, cmd_offset + 12, endian);
    const stroff = try readU32At(file, cmd_offset + 16, endian);
    const strsize = try readU32At(file, cmd_offset + 20, endian);

    const sym_id = try result.addEntity(.{
        .kind = types.EntityKind.SymtabCommand,
        .range = .{ .offset = cmd_offset, .size = fixed_size },
    });
    try result.addContainment(.Owns, cmd_id, sym_id);

    try result.symtab_commands.append(.{
        .cmd = 0x2,
        .cmdsize = cmdsize,
        .symoff = symoff,
        .nsyms = nsyms,
        .stroff = stroff,
        .strsize = strsize,
        .cmd_range = .{ .offset = cmd_offset + 0, .size = 4 },
        .cmdsize_range = .{ .offset = cmd_offset + 4, .size = 4 },
        .symoff_range = .{ .offset = cmd_offset + 8, .size = 4 },
        .nsyms_range = .{ .offset = cmd_offset + 12, .size = 4 },
        .stroff_range = .{ .offset = cmd_offset + 16, .size = 4 },
        .strsize_range = .{ .offset = cmd_offset + 20, .size = 4 },
        .entity = sym_id,
    });

    return .{ .handled = true, .consumed = fixed_size };
}

fn parseDysymtab(
    result: *ParseResult,
    file: std.fs.File,
    cmd_id: types.EntityId,
    cmd_offset: u64,
    cmdsize: u32,
    endian: std.builtin.Endian,
) !TypedParseResult {
    const fixed_size: u64 = 80;
    if (cmdsize < fixed_size) {
        try result.addDiagnostic(.load_cmd_typed_truncated, .Error, .{ .offset = cmd_offset, .size = cmdsize });
        return .{ .handled = true, .consumed = 0 };
    }

    const ilocalsym = try readU32At(file, cmd_offset + 8, endian);
    const nlocalsym = try readU32At(file, cmd_offset + 12, endian);
    const iextdefsym = try readU32At(file, cmd_offset + 16, endian);
    const nextdefsym = try readU32At(file, cmd_offset + 20, endian);
    const iundefsym = try readU32At(file, cmd_offset + 24, endian);
    const nundefsym = try readU32At(file, cmd_offset + 28, endian);
    const tocoff = try readU32At(file, cmd_offset + 32, endian);
    const ntoc = try readU32At(file, cmd_offset + 36, endian);
    const modtaboff = try readU32At(file, cmd_offset + 40, endian);
    const nmodtab = try readU32At(file, cmd_offset + 44, endian);
    const extrefsymoff = try readU32At(file, cmd_offset + 48, endian);
    const nextrefsyms = try readU32At(file, cmd_offset + 52, endian);
    const indirectsymoff = try readU32At(file, cmd_offset + 56, endian);
    const nindirectsyms = try readU32At(file, cmd_offset + 60, endian);
    const extreloff = try readU32At(file, cmd_offset + 64, endian);
    const nextrel = try readU32At(file, cmd_offset + 68, endian);
    const locreloff = try readU32At(file, cmd_offset + 72, endian);
    const nlocrel = try readU32At(file, cmd_offset + 76, endian);

    const dysym_id = try result.addEntity(.{
        .kind = types.EntityKind.DysymtabCommand,
        .range = .{ .offset = cmd_offset, .size = fixed_size },
    });
    try result.addContainment(.Owns, cmd_id, dysym_id);

    try result.dysymtab_commands.append(.{
        .cmd = 0xb,
        .cmdsize = cmdsize,
        .ilocalsym = ilocalsym,
        .nlocalsym = nlocalsym,
        .iextdefsym = iextdefsym,
        .nextdefsym = nextdefsym,
        .iundefsym = iundefsym,
        .nundefsym = nundefsym,
        .tocoff = tocoff,
        .ntoc = ntoc,
        .modtaboff = modtaboff,
        .nmodtab = nmodtab,
        .extrefsymoff = extrefsymoff,
        .nextrefsyms = nextrefsyms,
        .indirectsymoff = indirectsymoff,
        .nindirectsyms = nindirectsyms,
        .extreloff = extreloff,
        .nextrel = nextrel,
        .locreloff = locreloff,
        .nlocrel = nlocrel,
        .cmd_range = .{ .offset = cmd_offset + 0, .size = 4 },
        .cmdsize_range = .{ .offset = cmd_offset + 4, .size = 4 },
        .ilocalsym_range = .{ .offset = cmd_offset + 8, .size = 4 },
        .nlocalsym_range = .{ .offset = cmd_offset + 12, .size = 4 },
        .iextdefsym_range = .{ .offset = cmd_offset + 16, .size = 4 },
        .nextdefsym_range = .{ .offset = cmd_offset + 20, .size = 4 },
        .iundefsym_range = .{ .offset = cmd_offset + 24, .size = 4 },
        .nundefsym_range = .{ .offset = cmd_offset + 28, .size = 4 },
        .tocoff_range = .{ .offset = cmd_offset + 32, .size = 4 },
        .ntoc_range = .{ .offset = cmd_offset + 36, .size = 4 },
        .modtaboff_range = .{ .offset = cmd_offset + 40, .size = 4 },
        .nmodtab_range = .{ .offset = cmd_offset + 44, .size = 4 },
        .extrefsymoff_range = .{ .offset = cmd_offset + 48, .size = 4 },
        .nextrefsyms_range = .{ .offset = cmd_offset + 52, .size = 4 },
        .indirectsymoff_range = .{ .offset = cmd_offset + 56, .size = 4 },
        .nindirectsyms_range = .{ .offset = cmd_offset + 60, .size = 4 },
        .extreloff_range = .{ .offset = cmd_offset + 64, .size = 4 },
        .nextrel_range = .{ .offset = cmd_offset + 68, .size = 4 },
        .locreloff_range = .{ .offset = cmd_offset + 72, .size = 4 },
        .nlocrel_range = .{ .offset = cmd_offset + 76, .size = 4 },
        .entity = dysym_id,
    });

    return .{ .handled = true, .consumed = fixed_size };
}

fn parseUuid(
    result: *ParseResult,
    file: std.fs.File,
    cmd_id: types.EntityId,
    cmd_offset: u64,
    cmdsize: u32,
) !TypedParseResult {
    const fixed_size: u64 = 24;
    if (cmdsize < fixed_size) {
        try result.addDiagnostic(.load_cmd_typed_truncated, .Error, .{ .offset = cmd_offset, .size = cmdsize });
        return .{ .handled = true, .consumed = 0 };
    }

    var uuid: [16]u8 = undefined;
    try readBytesAt(file, cmd_offset + 8, uuid[0..]);

    const uuid_id = try result.addEntity(.{
        .kind = types.EntityKind.UuidCommand,
        .range = .{ .offset = cmd_offset, .size = fixed_size },
    });
    try result.addContainment(.Owns, cmd_id, uuid_id);

    try result.uuid_commands.append(.{
        .cmd = 0x1b,
        .cmdsize = cmdsize,
        .uuid = uuid,
        .cmd_range = .{ .offset = cmd_offset + 0, .size = 4 },
        .cmdsize_range = .{ .offset = cmd_offset + 4, .size = 4 },
        .uuid_range = .{ .offset = cmd_offset + 8, .size = 16 },
        .entity = uuid_id,
    });

    return .{ .handled = true, .consumed = fixed_size };
}

fn parseBuildVersion(
    result: *ParseResult,
    file: std.fs.File,
    cmd_id: types.EntityId,
    cmd_offset: u64,
    cmdsize: u32,
    endian: std.builtin.Endian,
) !TypedParseResult {
    const fixed_size: u64 = 24;
    if (cmdsize < fixed_size) {
        try result.addDiagnostic(.load_cmd_typed_truncated, .Error, .{ .offset = cmd_offset, .size = cmdsize });
        return .{ .handled = true, .consumed = 0 };
    }

    const platform = try readU32At(file, cmd_offset + 8, endian);
    const minos = try readU32At(file, cmd_offset + 12, endian);
    const sdk = try readU32At(file, cmd_offset + 16, endian);
    const ntools = try readU32At(file, cmd_offset + 20, endian);

    const build_id = try result.addEntity(.{
        .kind = types.EntityKind.BuildVersionCommand,
        .range = .{ .offset = cmd_offset, .size = fixed_size },
    });
    try result.addContainment(.Owns, cmd_id, build_id);

    try result.build_version_commands.append(.{
        .cmd = 0x32,
        .cmdsize = cmdsize,
        .platform = platform,
        .minos = minos,
        .sdk = sdk,
        .ntools = ntools,
        .cmd_range = .{ .offset = cmd_offset + 0, .size = 4 },
        .cmdsize_range = .{ .offset = cmd_offset + 4, .size = 4 },
        .platform_range = .{ .offset = cmd_offset + 8, .size = 4 },
        .minos_range = .{ .offset = cmd_offset + 12, .size = 4 },
        .sdk_range = .{ .offset = cmd_offset + 16, .size = 4 },
        .ntools_range = .{ .offset = cmd_offset + 20, .size = 4 },
        .entity = build_id,
    });

    const tools_offset = cmd_offset + fixed_size;
    const available = @as(u64, cmdsize) - fixed_size;
    const tool_size: u64 = 8;
    const max_tools = available / tool_size;
    const parse_count: u64 = @min(@as(u64, ntools), max_tools);

    if (@as(u64, ntools) > max_tools) {
        try result.addDiagnostic(.load_cmd_tools_truncated, .Error, .{ .offset = tools_offset, .size = available });
    }

    var i: u64 = 0;
    while (i < parse_count) : (i += 1) {
        const tool_offset = tools_offset + i * tool_size;
        const tool = try readU32At(file, tool_offset + 0, endian);
        const version = try readU32At(file, tool_offset + 4, endian);

        const tool_id = try result.addEntity(.{
            .kind = types.EntityKind.BuildToolVersion,
            .range = .{ .offset = tool_offset, .size = tool_size },
        });
        try result.addContainment(.Owns, build_id, tool_id);

        try result.build_tool_versions.append(.{
            .tool = tool,
            .version = version,
            .tool_range = .{ .offset = tool_offset + 0, .size = 4 },
            .version_range = .{ .offset = tool_offset + 4, .size = 4 },
            .entity = tool_id,
        });
    }

    const consumed = fixed_size + parse_count * tool_size;
    return .{ .handled = true, .consumed = consumed };
}

fn emitRegionPadding(result: *ParseResult, region_id: types.EntityId, offset: u64, region_end: u64) !void {
    if (offset >= region_end) return;
    const size = region_end - offset;
    const pad_id = try result.addEntity(.{
        .kind = types.EntityKind.LoadCommandPadding,
        .range = .{ .offset = offset, .size = size },
    });
    try result.addContainment(.Owns, region_id, pad_id);
}

fn readBytesAt(file: std.fs.File, offset: u64, buf: []u8) !void {
    const read_len = try file.preadAll(buf, offset);
    if (read_len < buf.len) return error.UnexpectedEof;
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
