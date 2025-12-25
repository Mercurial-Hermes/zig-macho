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
