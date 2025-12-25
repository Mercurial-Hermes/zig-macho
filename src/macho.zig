const std = @import("std");
const load_cmds = @import("macho_load_commands.zig");
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

    // Stage: structural closure (gaps and ordering).
    try emitGaps(&result);

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
    const nfat_arch = try load_cmds.readU32At(file, 4, endian);

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

        const cputype = try load_cmds.readU32At(file, entry_offset + 0, endian);
        const cpusubtype = try load_cmds.readU32At(file, entry_offset + 4, endian);
        var offset: u64 = 0;
        var size: u64 = 0;
        var alignment: u32 = 0;
        var reserved: u32 = 0;

        if (magic.is_fat_64) {
            offset = try load_cmds.readU64At(file, entry_offset + 8, endian);
            size = try load_cmds.readU64At(file, entry_offset + 16, endian);
            alignment = try load_cmds.readU32At(file, entry_offset + 24, endian);
            reserved = try load_cmds.readU32At(file, entry_offset + 28, endian);
        } else {
            offset = @as(u64, try load_cmds.readU32At(file, entry_offset + 8, endian));
            size = @as(u64, try load_cmds.readU32At(file, entry_offset + 12, endian));
            alignment = try load_cmds.readU32At(file, entry_offset + 16, endian);
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

        if (!load_cmds.rangeInBounds(result.file_size, offset, size)) {
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

        if (!load_cmds.rangeInBounds(result.file_size, slice_offset, 4)) {
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
        const cputype = try load_cmds.readU32At(file, slice_offset + 4, endian);
        const cpusubtype = try load_cmds.readU32At(file, slice_offset + 8, endian);
        const filetype = try load_cmds.readU32At(file, slice_offset + 12, endian);
        const ncmds = try load_cmds.readU32At(file, slice_offset + 16, endian);
        const sizeofcmds = try load_cmds.readU32At(file, slice_offset + 20, endian);
        const flags = try load_cmds.readU32At(file, slice_offset + 24, endian);
        const reserved = if (magic.is_64) try load_cmds.readU32At(file, slice_offset + 28, endian) else 0;

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

        try load_cmds.parseLoadCommands(result, file, slice_entity, header_id, header_size, ncmds, sizeofcmds, magic.endian);
    }
}

const ChildRange = struct {
    child: types.EntityId,
    range: types.ByteRange,
};

fn shouldEmitGaps(kind: types.EntityKind) bool {
    return switch (kind) {
        .File, .Slice, .LoadCommandsRegion, .LoadCommand => true,
        else => false,
    };
}

fn emitGaps(result: *ParseResult) !void {
    const allocator = result.allocator;
    const initial_entities_len = result.entities.items.len;

    var children = try allocator.alloc(std.ArrayList(ChildRange), initial_entities_len);
    defer {
        var idx: usize = 0;
        while (idx < initial_entities_len) : (idx += 1) {
            children[idx].deinit();
        }
        allocator.free(children);
    }

    var i: usize = 0;
    while (i < initial_entities_len) : (i += 1) {
        children[i] = std.ArrayList(ChildRange).init(allocator);
    }

    for (result.containments.items) |edge| {
        const parent_index: usize = @intCast(edge.parent.index);
        const child_index: usize = @intCast(edge.child.index);
        if (parent_index >= initial_entities_len or child_index >= initial_entities_len) continue;
        const child_entity = result.entities.items[child_index];
        try children[parent_index].append(.{ .child = edge.child, .range = child_entity.range });
    }

    i = 0;
    while (i < initial_entities_len) : (i += 1) {
        const parent_entity = result.entities.items[i];
        if (!shouldEmitGaps(parent_entity.kind)) continue;
        if (children[i].items.len == 0) continue;

        const parent_start = parent_entity.range.offset;
        const parent_end = std.math.add(u64, parent_entity.range.offset, parent_entity.range.size) catch parent_entity.range.offset;

        std.sort.heap(ChildRange, children[i].items, {}, struct {
            fn lessThan(_: void, a: ChildRange, b: ChildRange) bool {
                if (a.range.offset == b.range.offset) {
                    if (a.range.size == b.range.size) return a.child.index < b.child.index;
                    return a.range.size < b.range.size;
                }
                return a.range.offset < b.range.offset;
            }
        }.lessThan);

        var cursor = parent_start;
        for (children[i].items) |child| {
            const child_start = child.range.offset;
            const child_end = std.math.add(u64, child.range.offset, child.range.size) catch child.range.offset;
            if (child_end <= parent_start or child_start >= parent_end) continue;
            const clamped_start = if (child_start < parent_start) parent_start else child_start;
            const clamped_end = if (child_end > parent_end) parent_end else child_end;
            if (clamped_start > cursor) {
                const gap_id = try result.addEntity(.{
                    .kind = types.EntityKind.Gap,
                    .range = .{ .offset = cursor, .size = clamped_start - cursor },
                });
                try result.addContainment(.Owns, .{ .index = @intCast(i) }, gap_id);
            }
            if (clamped_end > cursor) cursor = clamped_end;
        }
        if (cursor < parent_end) {
            const gap_id = try result.addEntity(.{
                .kind = types.EntityKind.Gap,
                .range = .{ .offset = cursor, .size = parent_end - cursor },
            });
            try result.addContainment(.Owns, .{ .index = @intCast(i) }, gap_id);
        }
    }

    try reorderContainments(result);
}

fn reorderContainments(result: *ParseResult) !void {
    const allocator = result.allocator;
    const entities_len = result.entities.items.len;

    var buckets = try allocator.alloc(std.ArrayList(types.Containment), entities_len);
    defer {
        var idx: usize = 0;
        while (idx < entities_len) : (idx += 1) {
            buckets[idx].deinit();
        }
        allocator.free(buckets);
    }

    var i: usize = 0;
    while (i < entities_len) : (i += 1) {
        buckets[i] = std.ArrayList(types.Containment).init(allocator);
    }

    for (result.containments.items) |edge| {
        const parent_index: usize = @intCast(edge.parent.index);
        if (parent_index >= entities_len) continue;
        try buckets[parent_index].append(edge);
    }

    const ctx = struct { result: *ParseResult }{ .result = result };
    for (buckets) |*bucket| {
        if (bucket.items.len == 0) continue;
        std.sort.heap(types.Containment, bucket.items, ctx, struct {
            fn lessThan(context: @TypeOf(ctx), a: types.Containment, b: types.Containment) bool {
                const a_index: usize = @intCast(a.child.index);
                const b_index: usize = @intCast(b.child.index);
                const a_entity = context.result.entities.items[a_index];
                const b_entity = context.result.entities.items[b_index];
                if (a_entity.range.offset == b_entity.range.offset) {
                    if (a_entity.range.size == b_entity.range.size) return a.child.index < b.child.index;
                    return a_entity.range.size < b_entity.range.size;
                }
                return a_entity.range.offset < b_entity.range.offset;
            }
        }.lessThan);
    }

    var new_list = std.ArrayList(types.Containment).init(allocator);
    for (buckets) |bucket| {
        try new_list.appendSlice(bucket.items);
    }

    result.containments.deinit();
    result.containments = new_list;
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
