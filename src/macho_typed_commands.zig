const std = @import("std");
const load_cmds = @import("macho_load_commands.zig");
const types = @import("types.zig");

const TypedParseResult = struct {
    handled: bool,
    consumed: u64,
};

// Stage: typed load command refinements (structural only).
pub fn parseTypedLoadCommand(
    result: anytype,
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
    result: anytype,
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
    try load_cmds.readBytesAt(file, cmd_offset + 8, segname[0..]);

    const vmaddr = try load_cmds.readU64At(file, cmd_offset + 24, endian);
    const vmsize = try load_cmds.readU64At(file, cmd_offset + 32, endian);
    const fileoff = try load_cmds.readU64At(file, cmd_offset + 40, endian);
    const filesize = try load_cmds.readU64At(file, cmd_offset + 48, endian);
    const maxprot = try load_cmds.readU32At(file, cmd_offset + 56, endian);
    const initprot = try load_cmds.readU32At(file, cmd_offset + 60, endian);
    const nsects = try load_cmds.readU32At(file, cmd_offset + 64, endian);
    const flags = try load_cmds.readU32At(file, cmd_offset + 68, endian);

    const segment_id = try result.addEntity(.{
        .kind = types.EntityKind.Segment64Command,
        .range = .{ .offset = cmd_offset, .size = fixed_size },
        .identity = .{ .index = 0 },
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
        try load_cmds.readBytesAt(file, sect_offset + 0, sectname[0..]);
        try load_cmds.readBytesAt(file, sect_offset + 16, segname2[0..]);
        const addr = try load_cmds.readU64At(file, sect_offset + 32, endian);
        const size = try load_cmds.readU64At(file, sect_offset + 40, endian);
        const offset_field = try load_cmds.readU32At(file, sect_offset + 48, endian);
        const alignment = try load_cmds.readU32At(file, sect_offset + 52, endian);
        const reloff = try load_cmds.readU32At(file, sect_offset + 56, endian);
        const nreloc = try load_cmds.readU32At(file, sect_offset + 60, endian);
        const flags_field = try load_cmds.readU32At(file, sect_offset + 64, endian);
        const reserved1 = try load_cmds.readU32At(file, sect_offset + 68, endian);
        const reserved2 = try load_cmds.readU32At(file, sect_offset + 72, endian);
        const reserved3 = try load_cmds.readU32At(file, sect_offset + 76, endian);

        const section_id = try result.addEntity(.{
            .kind = types.EntityKind.Section64,
            .range = .{ .offset = sect_offset, .size = section_size },
            .identity = .{ .index = 0 },
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
    result: anytype,
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

    const symoff = try load_cmds.readU32At(file, cmd_offset + 8, endian);
    const nsyms = try load_cmds.readU32At(file, cmd_offset + 12, endian);
    const stroff = try load_cmds.readU32At(file, cmd_offset + 16, endian);
    const strsize = try load_cmds.readU32At(file, cmd_offset + 20, endian);

    const sym_id = try result.addEntity(.{
        .kind = types.EntityKind.SymtabCommand,
        .range = .{ .offset = cmd_offset, .size = fixed_size },
        .identity = .{ .index = 0 },
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
    result: anytype,
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

    const ilocalsym = try load_cmds.readU32At(file, cmd_offset + 8, endian);
    const nlocalsym = try load_cmds.readU32At(file, cmd_offset + 12, endian);
    const iextdefsym = try load_cmds.readU32At(file, cmd_offset + 16, endian);
    const nextdefsym = try load_cmds.readU32At(file, cmd_offset + 20, endian);
    const iundefsym = try load_cmds.readU32At(file, cmd_offset + 24, endian);
    const nundefsym = try load_cmds.readU32At(file, cmd_offset + 28, endian);
    const tocoff = try load_cmds.readU32At(file, cmd_offset + 32, endian);
    const ntoc = try load_cmds.readU32At(file, cmd_offset + 36, endian);
    const modtaboff = try load_cmds.readU32At(file, cmd_offset + 40, endian);
    const nmodtab = try load_cmds.readU32At(file, cmd_offset + 44, endian);
    const extrefsymoff = try load_cmds.readU32At(file, cmd_offset + 48, endian);
    const nextrefsyms = try load_cmds.readU32At(file, cmd_offset + 52, endian);
    const indirectsymoff = try load_cmds.readU32At(file, cmd_offset + 56, endian);
    const nindirectsyms = try load_cmds.readU32At(file, cmd_offset + 60, endian);
    const extreloff = try load_cmds.readU32At(file, cmd_offset + 64, endian);
    const nextrel = try load_cmds.readU32At(file, cmd_offset + 68, endian);
    const locreloff = try load_cmds.readU32At(file, cmd_offset + 72, endian);
    const nlocrel = try load_cmds.readU32At(file, cmd_offset + 76, endian);

    const dysym_id = try result.addEntity(.{
        .kind = types.EntityKind.DysymtabCommand,
        .range = .{ .offset = cmd_offset, .size = fixed_size },
        .identity = .{ .index = 0 },
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
    result: anytype,
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
    try load_cmds.readBytesAt(file, cmd_offset + 8, uuid[0..]);

    const uuid_id = try result.addEntity(.{
        .kind = types.EntityKind.UuidCommand,
        .range = .{ .offset = cmd_offset, .size = fixed_size },
        .identity = .{ .index = 0 },
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
    result: anytype,
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

    const platform = try load_cmds.readU32At(file, cmd_offset + 8, endian);
    const minos = try load_cmds.readU32At(file, cmd_offset + 12, endian);
    const sdk = try load_cmds.readU32At(file, cmd_offset + 16, endian);
    const ntools = try load_cmds.readU32At(file, cmd_offset + 20, endian);

    const build_id = try result.addEntity(.{
        .kind = types.EntityKind.BuildVersionCommand,
        .range = .{ .offset = cmd_offset, .size = fixed_size },
        .identity = .{ .index = 0 },
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
        const tool = try load_cmds.readU32At(file, tool_offset + 0, endian);
        const version = try load_cmds.readU32At(file, tool_offset + 4, endian);

        const tool_id = try result.addEntity(.{
            .kind = types.EntityKind.BuildToolVersion,
            .range = .{ .offset = tool_offset, .size = tool_size },
            .identity = .{ .index = 0 },
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
