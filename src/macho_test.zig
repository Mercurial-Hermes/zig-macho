const std = @import("std");
const macho = @import("macho.zig");

fn writeU32(buf: []u8, offset: usize, value: u32, endian: std.builtin.Endian) void {
    const ptr: *[4]u8 = @ptrCast(buf[offset .. offset + 4].ptr);
    std.mem.writeInt(u32, ptr, value, endian);
}

fn writeU64(buf: []u8, offset: usize, value: u64, endian: std.builtin.Endian) void {
    const ptr: *[8]u8 = @ptrCast(buf[offset .. offset + 8].ptr);
    std.mem.writeInt(u64, ptr, value, endian);
}

fn writeTempFile(tmp: std.testing.TmpDir, allocator: std.mem.Allocator, name: []const u8, data: []const u8) ![]u8 {
    {
        var file = try tmp.dir.createFile(name, .{});
        defer file.close();
        try file.writeAll(data);
    }

    return try tmp.dir.realpathAlloc(allocator, name);
}

fn countEntities(result: *const macho.ParseResult, kind: macho.types.EntityKind) usize {
    var count: usize = 0;
    for (result.entities.items) |entity| {
        if (entity.kind == kind) count += 1;
    }
    return count;
}

fn entityAt(result: *const macho.ParseResult, id: macho.types.EntityId) macho.types.Entity {
    return result.entities.items[@intCast(id.index)];
}

fn hasContainment(
    result: *const macho.ParseResult,
    kind: macho.types.ContainmentKind,
    parent: macho.types.EntityId,
    child: macho.types.EntityId,
) bool {
    for (result.containments.items) |edge| {
        if (edge.kind == kind and edge.parent.index == parent.index and edge.child.index == child.index) {
            return true;
        }
    }
    return false;
}

fn findParent(
    result: *const macho.ParseResult,
    kind: macho.types.ContainmentKind,
    child: macho.types.EntityId,
) ?macho.types.EntityId {
    for (result.containments.items) |edge| {
        if (edge.kind == kind and edge.child.index == child.index) {
            return edge.parent;
        }
    }
    return null;
}

fn rangesNonOverlappingAndContained(ranges: []const macho.types.ByteRange, container: macho.types.ByteRange) bool {
    var i: usize = 0;
    while (i < ranges.len) : (i += 1) {
        const a = ranges[i];
        if (a.size == 0) return false;
        if (a.offset < container.offset) return false;
        if (a.offset + a.size > container.offset + container.size) return false;
        var j: usize = i + 1;
        while (j < ranges.len) : (j += 1) {
            const b = ranges[j];
            if (!(a.offset + a.size <= b.offset or b.offset + b.size <= a.offset)) return false;
        }
    }
    return true;
}

test "parse: file size is detected" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const data = "abcdef";
    const path = try writeTempFile(tmp, allocator, "size.bin", data);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(u64, data.len), result.file_size);
}

test "parse: file entity range spans entire file" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const data = "zig-macho";
    const path = try writeTempFile(tmp, allocator, "range.bin", data);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    const entity = result.entities.items[0];
    try std.testing.expectEqual(macho.types.EntityKind.File, entity.kind);
    try std.testing.expectEqual(@as(u64, 0), entity.range.offset);
    try std.testing.expectEqual(@as(u64, data.len), entity.range.size);
}

test "parse: no diagnostics for valid file" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const buf = try allocator.alloc(u8, 28);
    defer allocator.free(buf);
    @memset(buf, 0);
    writeU32(buf, 0, 0xfeedface, .big);
    writeU32(buf, 4, 0x0100000c, .big);
    writeU32(buf, 8, 0, .big);
    writeU32(buf, 12, 2, .big);
    writeU32(buf, 16, 0, .big);
    writeU32(buf, 20, 0, .big);
    writeU32(buf, 24, 0, .big);
    writeU32(buf, 4, 0x0100000c, .big);
    writeU32(buf, 8, 0, .big);
    writeU32(buf, 12, 2, .big);
    writeU32(buf, 16, 0, .big);
    writeU32(buf, 20, 0, .big);
    writeU32(buf, 24, 0, .big);

    const path = try writeTempFile(tmp, allocator, "clean.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.diagnostics.items.len);
}

test "parse: deterministic entity tables" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buf = [_]u8{ 'r', 'e', 'p', 'e', 'a', 't' };
    const path = try writeTempFile(tmp, allocator, "repeat.bin", buf[0..]);
    defer allocator.free(path);

    var first = try macho.parseFile(allocator, path);
    defer first.deinit();

    var second = try macho.parseFile(allocator, path);
    defer second.deinit();

    try std.testing.expectEqual(first.file_size, second.file_size);
    try std.testing.expectEqual(first.entities.items.len, second.entities.items.len);

    const a = first.entities.items[0];
    const b = second.entities.items[0];
    try std.testing.expectEqual(a.kind, b.kind);
    try std.testing.expectEqual(a.range.offset, b.range.offset);
    try std.testing.expectEqual(a.range.size, b.range.size);

    try std.testing.expectEqual(first.diagnostics.items.len, second.diagnostics.items.len);
}

test "fat: emits slices for each arch entry" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const entry_size: usize = 20;
    const header_size: usize = 8;
    const nfat_arch: u32 = 2;
    const slice_offset_0: u32 = 64;
    const slice_size_0: u32 = 64;
    const slice_offset_1: u32 = 96;
    const slice_size_1: u32 = 32;
    const file_size: usize = 160;

    const buf = try allocator.alloc(u8, file_size);
    defer allocator.free(buf);
    @memset(buf, 0);

    writeU32(buf, 0, 0xcafebabe, .big);
    writeU32(buf, 4, nfat_arch, .big);

    const entry0 = header_size + 0 * entry_size;
    writeU32(buf, entry0 + 0, 0x0100000c, .big);
    writeU32(buf, entry0 + 4, 0, .big);
    writeU32(buf, entry0 + 8, slice_offset_0, .big);
    writeU32(buf, entry0 + 12, slice_size_0, .big);
    writeU32(buf, entry0 + 16, 0, .big);

    const entry1 = header_size + 1 * entry_size;
    writeU32(buf, entry1 + 0, 0x01000007, .big);
    writeU32(buf, entry1 + 4, 0, .big);
    writeU32(buf, entry1 + 8, slice_offset_1, .big);
    writeU32(buf, entry1 + 12, slice_size_1, .big);
    writeU32(buf, entry1 + 16, 0, .big);

    writeU32(buf, slice_offset_0, 0xfeedfacf, .big);
    writeU32(buf, slice_offset_0 + 4, 0x0100000c, .big);
    writeU32(buf, slice_offset_0 + 8, 0, .big);
    writeU32(buf, slice_offset_0 + 12, 2, .big);
    writeU32(buf, slice_offset_0 + 16, 0, .big);
    writeU32(buf, slice_offset_0 + 20, 0, .big);
    writeU32(buf, slice_offset_0 + 24, 0, .big);
    writeU32(buf, slice_offset_0 + 28, 0, .big);

    writeU32(buf, slice_offset_1, 0xfeedface, .big);
    writeU32(buf, slice_offset_1 + 4, 0x01000007, .big);
    writeU32(buf, slice_offset_1 + 8, 0, .big);
    writeU32(buf, slice_offset_1 + 12, 2, .big);
    writeU32(buf, slice_offset_1 + 16, 0, .big);
    writeU32(buf, slice_offset_1 + 20, 0, .big);
    writeU32(buf, slice_offset_1 + 24, 0, .big);

    const path = try writeTempFile(tmp, allocator, "fat.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.fat_headers.items.len);
    try std.testing.expectEqual(@as(usize, 2), result.fat_arch_entries.items.len);
    try std.testing.expectEqual(@as(usize, 2), countEntities(&result, macho.types.EntityKind.Slice));
    try std.testing.expectEqual(@as(usize, 2), result.mach_headers.items.len);

    const first_entry = result.fat_arch_entries.items[0];
    const first_slice = entityAt(&result, first_entry.slice);
    try std.testing.expectEqual(@as(u64, slice_offset_0), first_slice.range.offset);
    try std.testing.expectEqual(@as(u64, slice_size_0), first_slice.range.size);

    const second_entry = result.fat_arch_entries.items[1];
    const second_slice = entityAt(&result, second_entry.slice);
    try std.testing.expectEqual(@as(u64, slice_offset_1), second_slice.range.offset);
    try std.testing.expectEqual(@as(u64, slice_size_1), second_slice.range.size);
}

test "thin: emits a single slice spanning the file" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const buf = try allocator.alloc(u8, 32);
    defer allocator.free(buf);
    @memset(buf, 0);

    writeU32(buf, 0, 0xfeedfacf, .big);
    writeU32(buf, 4, 0x0100000c, .big);
    writeU32(buf, 8, 0, .big);
    writeU32(buf, 12, 2, .big);
    writeU32(buf, 16, 0, .big);
    writeU32(buf, 20, 0, .big);
    writeU32(buf, 24, 0, .big);
    writeU32(buf, 28, 0, .big);

    const path = try writeTempFile(tmp, allocator, "thin.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.fat_headers.items.len);
    try std.testing.expectEqual(@as(usize, 1), countEntities(&result, macho.types.EntityKind.Slice));
    try std.testing.expectEqual(@as(usize, 1), result.mach_headers.items.len);

    const slice_entity = result.entities.items[1];
    try std.testing.expectEqual(@as(u64, 0), slice_entity.range.offset);
    try std.testing.expectEqual(@as(u64, 32), slice_entity.range.size);
}

test "thin: mach header range reflects 32-bit size" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const buf = try allocator.alloc(u8, 28);
    defer allocator.free(buf);
    @memset(buf, 0);

    writeU32(buf, 0, 0xfeedface, .big);

    const path = try writeTempFile(tmp, allocator, "header32.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.mach_headers.items.len);
    const header_entity = result.entities.items[2];
    try std.testing.expectEqual(@as(u64, 28), header_entity.range.size);
}

test "thin: slice owns mach header containment" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const buf = try allocator.alloc(u8, 28);
    defer allocator.free(buf);
    @memset(buf, 0);
    writeU32(buf, 0, 0xfeedface, .big);
    writeU32(buf, 4, 0x0100000c, .big);
    writeU32(buf, 8, 0, .big);
    writeU32(buf, 12, 2, .big);
    writeU32(buf, 16, 0, .big);
    writeU32(buf, 20, 0, .big);
    writeU32(buf, 24, 0, .big);

    const path = try writeTempFile(tmp, allocator, "containment.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), countEntities(&result, macho.types.EntityKind.Slice));
    try std.testing.expectEqual(@as(usize, 1), result.mach_headers.items.len);

    const slice_id = result.slice_entities.items[0];
    const header_id = result.mach_headers.items[0].entity;
    try std.testing.expect(hasContainment(&result, .Owns, slice_id, header_id));
}

test "thin: load command region and commands are ordered" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const header_size: usize = 28;
    const cmd0_size: u32 = 8;
    const cmd1_size: u32 = 12;
    const sizeofcmds: u32 = cmd0_size + cmd1_size;
    const file_size: usize = header_size + sizeofcmds;

    const buf = try allocator.alloc(u8, file_size);
    defer allocator.free(buf);
    @memset(buf, 0);

    writeU32(buf, 0, 0xfeedface, .big);
    writeU32(buf, 4, 0x0100000c, .big);
    writeU32(buf, 8, 0, .big);
    writeU32(buf, 12, 2, .big);
    writeU32(buf, 16, 2, .big);
    writeU32(buf, 20, sizeofcmds, .big);
    writeU32(buf, 24, 0, .big);

    const cmd0_offset = header_size;
    writeU32(buf, cmd0_offset + 0, 0x1, .big);
    writeU32(buf, cmd0_offset + 4, cmd0_size, .big);

    const cmd1_offset = cmd0_offset + cmd0_size;
    writeU32(buf, cmd1_offset + 0, 0x3, .big);
    writeU32(buf, cmd1_offset + 4, cmd1_size, .big);

    const path = try writeTempFile(tmp, allocator, "loadcmds.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.load_cmd_regions.items.len);
    try std.testing.expectEqual(@as(usize, 2), result.load_commands.items.len);

    const region_entity = entityAt(&result, result.load_cmd_regions.items[0].entity);
    try std.testing.expectEqual(@as(u64, header_size), region_entity.range.offset);
    try std.testing.expectEqual(@as(u64, sizeofcmds), region_entity.range.size);

    const cmd0_entity = entityAt(&result, result.load_commands.items[0].entity);
    const cmd1_entity = entityAt(&result, result.load_commands.items[1].entity);
    try std.testing.expectEqual(@as(u64, cmd0_offset), cmd0_entity.range.offset);
    try std.testing.expectEqual(@as(u64, cmd0_size), cmd0_entity.range.size);
    try std.testing.expectEqual(@as(u64, cmd1_offset), cmd1_entity.range.offset);
    try std.testing.expectEqual(@as(u64, cmd1_size), cmd1_entity.range.size);
}

test "thin: load command region owns load commands" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const header_size: usize = 28;
    const cmd0_size: u32 = 8;
    const cmd1_size: u32 = 12;
    const sizeofcmds: u32 = cmd0_size + cmd1_size;
    const file_size: usize = header_size + sizeofcmds;

    const buf = try allocator.alloc(u8, file_size);
    defer allocator.free(buf);
    @memset(buf, 0);

    writeU32(buf, 0, 0xfeedface, .big);
    writeU32(buf, 4, 0x0100000c, .big);
    writeU32(buf, 8, 0, .big);
    writeU32(buf, 12, 2, .big);
    writeU32(buf, 16, 2, .big);
    writeU32(buf, 20, sizeofcmds, .big);
    writeU32(buf, 24, 0, .big);

    const cmd0_offset = header_size;
    writeU32(buf, cmd0_offset + 0, 0x1, .big);
    writeU32(buf, cmd0_offset + 4, cmd0_size, .big);

    const cmd1_offset = cmd0_offset + cmd0_size;
    writeU32(buf, cmd1_offset + 0, 0x3, .big);
    writeU32(buf, cmd1_offset + 4, cmd1_size, .big);

    const path = try writeTempFile(tmp, allocator, "loadcmds_owns.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.load_cmd_regions.items.len);
    try std.testing.expectEqual(@as(usize, 2), result.load_commands.items.len);

    const region_id = result.load_cmd_regions.items[0].entity;
    const cmd0_id = result.load_commands.items[0].entity;
    const cmd1_id = result.load_commands.items[1].entity;

    try std.testing.expect(hasContainment(&result, .Owns, region_id, cmd0_id));
    try std.testing.expect(hasContainment(&result, .Owns, region_id, cmd1_id));
}

test "thin64: typed load commands and sections are contained" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const header_size: usize = 32;
    const segment_cmdsize: u32 = 72 + 80;
    const symtab_cmdsize: u32 = 24;
    const uuid_cmdsize: u32 = 24;
    const build_cmdsize: u32 = 24 + 8;
    const sizeofcmds: u32 = segment_cmdsize + symtab_cmdsize + uuid_cmdsize + build_cmdsize;
    const file_size: usize = header_size + sizeofcmds;

    const buf = try allocator.alloc(u8, file_size);
    defer allocator.free(buf);
    @memset(buf, 0);

    writeU32(buf, 0, 0xfeedfacf, .big);
    writeU32(buf, 4, 0x0100000c, .big);
    writeU32(buf, 8, 0, .big);
    writeU32(buf, 12, 2, .big);
    writeU32(buf, 16, 4, .big);
    writeU32(buf, 20, sizeofcmds, .big);
    writeU32(buf, 24, 0, .big);
    writeU32(buf, 28, 0, .big);

    var offset: usize = header_size;

    writeU32(buf, offset + 0, 0x19, .big);
    writeU32(buf, offset + 4, segment_cmdsize, .big);
    writeU32(buf, offset + 64, 1, .big);
    const sect_offset = offset + 72;
    writeU32(buf, sect_offset + 48, 0, .big);
    writeU32(buf, sect_offset + 52, 0, .big);
    writeU32(buf, sect_offset + 56, 0, .big);
    writeU32(buf, sect_offset + 60, 0, .big);
    writeU32(buf, sect_offset + 64, 0, .big);
    writeU32(buf, sect_offset + 68, 0, .big);
    writeU32(buf, sect_offset + 72, 0, .big);
    writeU32(buf, sect_offset + 76, 0, .big);

    offset += segment_cmdsize;
    writeU32(buf, offset + 0, 0x2, .big);
    writeU32(buf, offset + 4, symtab_cmdsize, .big);
    offset += symtab_cmdsize;
    writeU32(buf, offset + 0, 0x1b, .big);
    writeU32(buf, offset + 4, uuid_cmdsize, .big);
    offset += uuid_cmdsize;
    writeU32(buf, offset + 0, 0x32, .big);
    writeU32(buf, offset + 4, build_cmdsize, .big);
    writeU32(buf, offset + 20, 1, .big);

    const path = try writeTempFile(tmp, allocator, "typed.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.segment64_commands.items.len);
    try std.testing.expectEqual(@as(usize, 1), result.section64_records.items.len);
    try std.testing.expectEqual(@as(usize, 1), result.symtab_commands.items.len);
    try std.testing.expectEqual(@as(usize, 1), result.uuid_commands.items.len);
    try std.testing.expectEqual(@as(usize, 1), result.build_version_commands.items.len);
    try std.testing.expectEqual(@as(usize, 1), result.build_tool_versions.items.len);

    const seg_id = result.segment64_commands.items[0].entity;
    const section_id = result.section64_records.items[0].entity;
    const seg_parent = findParent(&result, .Owns, seg_id) orelse return error.TestUnexpectedResult;
    try std.testing.expect(hasContainment(&result, .Owns, seg_parent, seg_id));
    try std.testing.expect(hasContainment(&result, .Owns, seg_id, section_id));

    const seg_entity = entityAt(&result, seg_id);
    try std.testing.expectEqual(@as(u64, header_size), seg_entity.range.offset);
    try std.testing.expectEqual(@as(u64, 72), seg_entity.range.size);

    const section_entity = entityAt(&result, section_id);
    try std.testing.expectEqual(@as(u64, header_size + 72), section_entity.range.offset);
    try std.testing.expectEqual(@as(u64, 80), section_entity.range.size);
}

test "thin: load command region padding is explicit" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const header_size: usize = 28;
    const sizeofcmds: u32 = 16;
    const file_size: usize = header_size + sizeofcmds;

    const buf = try allocator.alloc(u8, file_size);
    defer allocator.free(buf);
    @memset(buf, 0);

    writeU32(buf, 0, 0xfeedface, .big);
    writeU32(buf, 4, 0x0100000c, .big);
    writeU32(buf, 8, 0, .big);
    writeU32(buf, 12, 2, .big);
    writeU32(buf, 16, 1, .big);
    writeU32(buf, 20, sizeofcmds, .big);
    writeU32(buf, 24, 0, .big);

    writeU32(buf, header_size + 0, 0x1, .big);
    writeU32(buf, header_size + 4, 8, .big);

    const path = try writeTempFile(tmp, allocator, "region_pad.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    var pad_count: usize = 0;
    for (result.entities.items) |entity| {
        if (entity.kind == macho.types.EntityKind.LoadCommandPadding) pad_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), result.load_cmd_regions.items.len);
    try std.testing.expectEqual(@as(usize, 1), pad_count);
}

test "thin64: segment command too small emits diagnostic" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const header_size: usize = 32;
    const segment_cmdsize: u32 = 64;
    const sizeofcmds: u32 = segment_cmdsize;
    const file_size: usize = header_size + sizeofcmds;

    const buf = try allocator.alloc(u8, file_size);
    defer allocator.free(buf);
    @memset(buf, 0);

    writeU32(buf, 0, 0xfeedfacf, .big);
    writeU32(buf, 4, 0x0100000c, .big);
    writeU32(buf, 8, 0, .big);
    writeU32(buf, 12, 2, .big);
    writeU32(buf, 16, 1, .big);
    writeU32(buf, 20, sizeofcmds, .big);
    writeU32(buf, 24, 0, .big);
    writeU32(buf, 28, 0, .big);

    writeU32(buf, header_size + 0, 0x19, .big);
    writeU32(buf, header_size + 4, segment_cmdsize, .big);

    const path = try writeTempFile(tmp, allocator, "seg_small.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.segment64_commands.items.len);
    try std.testing.expectEqual(@as(usize, 1), result.diagnostics.items.len);
    try std.testing.expectEqual(macho.types.DiagnosticCode.load_cmd_typed_truncated, result.diagnostics.items[0].code);
}

test "thin64: truncated section table emits diagnostic" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const header_size: usize = 32;
    const segment_cmdsize: u32 = 72 + 80;
    const sizeofcmds: u32 = segment_cmdsize;
    const file_size: usize = header_size + sizeofcmds;

    const buf = try allocator.alloc(u8, file_size);
    defer allocator.free(buf);
    @memset(buf, 0);

    writeU32(buf, 0, 0xfeedfacf, .big);
    writeU32(buf, 4, 0x0100000c, .big);
    writeU32(buf, 8, 0, .big);
    writeU32(buf, 12, 2, .big);
    writeU32(buf, 16, 1, .big);
    writeU32(buf, 20, sizeofcmds, .big);
    writeU32(buf, 24, 0, .big);
    writeU32(buf, 28, 0, .big);

    writeU32(buf, header_size + 0, 0x19, .big);
    writeU32(buf, header_size + 4, segment_cmdsize, .big);
    writeU32(buf, header_size + 64, 2, .big);

    const path = try writeTempFile(tmp, allocator, "sect_trunc.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.section64_records.items.len);
    try std.testing.expectEqual(@as(usize, 1), result.diagnostics.items.len);
    try std.testing.expectEqual(macho.types.DiagnosticCode.load_cmd_sections_truncated, result.diagnostics.items[0].code);
}

test "thin64: dysymtab field ranges are contained and non-overlapping" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const header_size: usize = 32;
    const cmdsize: u32 = 80;
    const sizeofcmds: u32 = cmdsize;
    const file_size: usize = header_size + sizeofcmds;

    const buf = try allocator.alloc(u8, file_size);
    defer allocator.free(buf);
    @memset(buf, 0);

    writeU32(buf, 0, 0xfeedfacf, .big);
    writeU32(buf, 4, 0x0100000c, .big);
    writeU32(buf, 8, 0, .big);
    writeU32(buf, 12, 2, .big);
    writeU32(buf, 16, 1, .big);
    writeU32(buf, 20, sizeofcmds, .big);
    writeU32(buf, 24, 0, .big);
    writeU32(buf, 28, 0, .big);

    writeU32(buf, header_size + 0, 0xb, .big);
    writeU32(buf, header_size + 4, cmdsize, .big);

    const path = try writeTempFile(tmp, allocator, "dysymtab.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.dysymtab_commands.items.len);
    const dysym_id = result.dysymtab_commands.items[0].entity;
    const parent_id = findParent(&result, .Owns, dysym_id) orelse return error.TestUnexpectedResult;
    const parent_entity = entityAt(&result, parent_id);
    try std.testing.expectEqual(macho.types.EntityKind.LoadCommand, parent_entity.kind);

    const dysym_entity = entityAt(&result, dysym_id);
    const d = result.dysymtab_commands.items[0];
    const ranges = [_]macho.types.ByteRange{
        d.cmd_range,
        d.cmdsize_range,
        d.ilocalsym_range,
        d.nlocalsym_range,
        d.iextdefsym_range,
        d.nextdefsym_range,
        d.iundefsym_range,
        d.nundefsym_range,
        d.tocoff_range,
        d.ntoc_range,
        d.modtaboff_range,
        d.nmodtab_range,
        d.extrefsymoff_range,
        d.nextrefsyms_range,
        d.indirectsymoff_range,
        d.nindirectsyms_range,
        d.extreloff_range,
        d.nextrel_range,
        d.locreloff_range,
        d.nlocrel_range,
    };
    try std.testing.expect(rangesNonOverlappingAndContained(&ranges, dysym_entity.range));
}

test "thin64: build version with zero tools emits padding" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const header_size: usize = 32;
    const cmdsize: u32 = 32;
    const sizeofcmds: u32 = cmdsize;
    const file_size: usize = header_size + sizeofcmds;

    const buf = try allocator.alloc(u8, file_size);
    defer allocator.free(buf);
    @memset(buf, 0);

    writeU32(buf, 0, 0xfeedfacf, .big);
    writeU32(buf, 4, 0x0100000c, .big);
    writeU32(buf, 8, 0, .big);
    writeU32(buf, 12, 2, .big);
    writeU32(buf, 16, 1, .big);
    writeU32(buf, 20, sizeofcmds, .big);
    writeU32(buf, 24, 0, .big);
    writeU32(buf, 28, 0, .big);

    writeU32(buf, header_size + 0, 0x32, .big);
    writeU32(buf, header_size + 4, cmdsize, .big);
    writeU32(buf, header_size + 20, 0, .big);

    const path = try writeTempFile(tmp, allocator, "build_zero.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.build_version_commands.items.len);
    try std.testing.expectEqual(@as(usize, 0), result.build_tool_versions.items.len);

    var pad_count: usize = 0;
    var pad_entity_id: ?macho.types.EntityId = null;
    for (result.entities.items, 0..) |entity, idx| {
        if (entity.kind == macho.types.EntityKind.LoadCommandPadding) {
            pad_count += 1;
            pad_entity_id = .{ .index = @intCast(idx) };
        }
    }
    try std.testing.expectEqual(@as(usize, 1), pad_count);

    const cmd_id = result.load_commands.items[0].entity;
    const pad_id = pad_entity_id orelse return error.TestUnexpectedResult;
    try std.testing.expect(hasContainment(&result, .Owns, cmd_id, pad_id));
}

test "thin: load command region out of bounds emits diagnostic" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const buf = try allocator.alloc(u8, 28);
    defer allocator.free(buf);
    @memset(buf, 0);

    writeU32(buf, 0, 0xfeedface, .big);
    writeU32(buf, 4, 0x0100000c, .big);
    writeU32(buf, 8, 0, .big);
    writeU32(buf, 12, 2, .big);
    writeU32(buf, 16, 1, .big);
    writeU32(buf, 20, 16, .big);
    writeU32(buf, 24, 0, .big);

    const path = try writeTempFile(tmp, allocator, "region_oob.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.load_cmd_regions.items.len);
    try std.testing.expectEqual(@as(usize, 0), result.load_commands.items.len);
    try std.testing.expectEqual(@as(usize, 1), result.diagnostics.items.len);
    try std.testing.expectEqual(macho.types.DiagnosticCode.load_cmd_region_out_of_bounds, result.diagnostics.items[0].code);
}

test "thin: malformed load command size emits diagnostic" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const header_size: usize = 28;
    const sizeofcmds: u32 = 16;
    const file_size: usize = header_size + sizeofcmds;

    const buf = try allocator.alloc(u8, file_size);
    defer allocator.free(buf);
    @memset(buf, 0);

    writeU32(buf, 0, 0xfeedface, .big);
    writeU32(buf, 4, 0x0100000c, .big);
    writeU32(buf, 8, 0, .big);
    writeU32(buf, 12, 2, .big);
    writeU32(buf, 16, 1, .big);
    writeU32(buf, 20, sizeofcmds, .big);
    writeU32(buf, 24, 0, .big);

    writeU32(buf, header_size + 0, 0x1, .big);
    writeU32(buf, header_size + 4, 4, .big);

    const path = try writeTempFile(tmp, allocator, "cmdsize_bad.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.load_cmd_regions.items.len);
    try std.testing.expectEqual(@as(usize, 0), result.load_commands.items.len);
    try std.testing.expectEqual(@as(usize, 1), result.diagnostics.items.len);
    try std.testing.expectEqual(macho.types.DiagnosticCode.load_cmd_malformed_size, result.diagnostics.items[0].code);
}

test "thin: truncated load command header emits diagnostic" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const header_size: usize = 28;
    const sizeofcmds: u32 = 4;
    const file_size: usize = header_size + sizeofcmds;

    const buf = try allocator.alloc(u8, file_size);
    defer allocator.free(buf);
    @memset(buf, 0);

    writeU32(buf, 0, 0xfeedface, .big);
    writeU32(buf, 4, 0x0100000c, .big);
    writeU32(buf, 8, 0, .big);
    writeU32(buf, 12, 2, .big);
    writeU32(buf, 16, 1, .big);
    writeU32(buf, 20, sizeofcmds, .big);
    writeU32(buf, 24, 0, .big);

    const path = try writeTempFile(tmp, allocator, "cmdheader_trunc.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.load_cmd_regions.items.len);
    try std.testing.expectEqual(@as(usize, 0), result.load_commands.items.len);
    try std.testing.expectEqual(@as(usize, 1), result.diagnostics.items.len);
    try std.testing.expectEqual(macho.types.DiagnosticCode.load_cmd_header_truncated, result.diagnostics.items[0].code);
}

test "fat: invalid mach header magic emits diagnostic" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const entry_size: usize = 20;
    const header_size: usize = 8;
    const nfat_arch: u32 = 1;
    const slice_offset: u32 = 32;
    const slice_size: u32 = 28;
    const file_size: usize = 64;

    const buf = try allocator.alloc(u8, file_size);
    defer allocator.free(buf);
    @memset(buf, 0);

    writeU32(buf, 0, 0xcafebabe, .big);
    writeU32(buf, 4, nfat_arch, .big);

    const entry0 = header_size + 0 * entry_size;
    writeU32(buf, entry0 + 0, 0x0100000c, .big);
    writeU32(buf, entry0 + 4, 0, .big);
    writeU32(buf, entry0 + 8, slice_offset, .big);
    writeU32(buf, entry0 + 12, slice_size, .big);
    writeU32(buf, entry0 + 16, 0, .big);

    const path = try writeTempFile(tmp, allocator, "badheader.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.diagnostics.items.len);
    try std.testing.expectEqual(@as(usize, 0), result.mach_headers.items.len);
    try std.testing.expectEqual(macho.types.DiagnosticCode.invalid_mach_magic, result.diagnostics.items[0].code);
}

test "thin: truncated mach header emits diagnostic" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const buf = try allocator.alloc(u8, 16);
    defer allocator.free(buf);
    @memset(buf, 0);
    writeU32(buf, 0, 0xfeedface, .big);

    const path = try writeTempFile(tmp, allocator, "shortheader.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.diagnostics.items.len);
    try std.testing.expectEqual(@as(usize, 0), result.mach_headers.items.len);
    try std.testing.expectEqual(macho.types.DiagnosticCode.mach_header_out_of_bounds, result.diagnostics.items[0].code);
}

test "parse: invalid magic emits diagnostic and no slices" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buf = [_]u8{ 0, 0, 0, 0, 0 };
    const path = try writeTempFile(tmp, allocator, "invalid.bin", buf[0..]);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.diagnostics.items.len);
    try std.testing.expectEqual(@as(usize, 0), countEntities(&result, macho.types.EntityKind.Slice));

    const diag = result.diagnostics.items[0];
    try std.testing.expectEqual(macho.types.DiagnosticCode.invalid_magic, diag.code);
    try std.testing.expectEqual(@as(u64, 0), diag.range.offset);
    try std.testing.expectEqual(@as(u64, 4), diag.range.size);
}

test "fat: out-of-bounds slice emits diagnostic" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const entry_size: usize = 20;
    const header_size: usize = 8;
    const nfat_arch: u32 = 1;
    const file_size: usize = 40;

    const buf = try allocator.alloc(u8, file_size);
    defer allocator.free(buf);
    @memset(buf, 0);

    writeU32(buf, 0, 0xcafebabe, .big);
    writeU32(buf, 4, nfat_arch, .big);

    const entry0 = header_size + 0 * entry_size;
    writeU32(buf, entry0 + 0, 0x0100000c, .big);
    writeU32(buf, entry0 + 4, 0, .big);
    writeU32(buf, entry0 + 8, 32, .big);
    writeU32(buf, entry0 + 12, 16, .big);
    writeU32(buf, entry0 + 16, 0, .big);

    const path = try writeTempFile(tmp, allocator, "oob.bin", buf);
    defer allocator.free(path);

    var result = try macho.parseFile(allocator, path);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), countEntities(&result, macho.types.EntityKind.Slice));
    try std.testing.expectEqual(@as(usize, 2), result.diagnostics.items.len);
    try std.testing.expectEqual(macho.types.DiagnosticCode.slice_out_of_bounds, result.diagnostics.items[0].code);
}
