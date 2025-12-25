const std = @import("std");
const macho = @import("macho.zig");
const types = @import("types.zig");

pub usingnamespace macho;

pub const ZmStatus = enum(c_int) {
    Ok = 0,
    IoError = 1,
    OutOfMemory = 2,
};

pub const ZmParseView = extern struct {
    file_size: u64,

    entities: ?[*]const types.Entity,
    entities_len: usize,

    identities: ?[*]const types.StructuralIdentity,
    identities_len: usize,

    diagnostics: ?[*]const types.Diagnostic,
    diagnostics_len: usize,

    containments: ?[*]const types.Containment,
    containments_len: usize,

    fat_headers: ?[*]const types.FatHeader,
    fat_headers_len: usize,

    fat_arch_entries: ?[*]const types.FatArchEntry,
    fat_arch_entries_len: usize,

    mach_headers: ?[*]const types.MachHeader,
    mach_headers_len: usize,

    load_cmd_regions: ?[*]const types.LoadCommandsRegion,
    load_cmd_regions_len: usize,

    load_commands: ?[*]const types.LoadCommand,
    load_commands_len: usize,

    segment64_commands: ?[*]const types.Segment64Command,
    segment64_commands_len: usize,

    section64_records: ?[*]const types.Section64,
    section64_records_len: usize,

    symtab_commands: ?[*]const types.SymtabCommand,
    symtab_commands_len: usize,

    dysymtab_commands: ?[*]const types.DysymtabCommand,
    dysymtab_commands_len: usize,

    uuid_commands: ?[*]const types.UuidCommand,
    uuid_commands_len: usize,

    build_version_commands: ?[*]const types.BuildVersionCommand,
    build_version_commands_len: usize,

    build_tool_versions: ?[*]const types.BuildToolVersion,
    build_tool_versions_len: usize,
};

fn slicePtr(comptime T: type, list: []const T) ?[*]const T {
    return if (list.len == 0) null else list.ptr;
}

fn fillView(result: *const macho.ParseResult, out: *ZmParseView) void {
    out.* = .{
        .file_size = result.file_size,
        .entities = slicePtr(types.Entity, result.entities.items),
        .entities_len = result.entities.items.len,
        .identities = slicePtr(types.StructuralIdentity, result.identities.items),
        .identities_len = result.identities.items.len,
        .diagnostics = slicePtr(types.Diagnostic, result.diagnostics.items),
        .diagnostics_len = result.diagnostics.items.len,
        .containments = slicePtr(types.Containment, result.containments.items),
        .containments_len = result.containments.items.len,
        .fat_headers = slicePtr(types.FatHeader, result.fat_headers.items),
        .fat_headers_len = result.fat_headers.items.len,
        .fat_arch_entries = slicePtr(types.FatArchEntry, result.fat_arch_entries.items),
        .fat_arch_entries_len = result.fat_arch_entries.items.len,
        .mach_headers = slicePtr(types.MachHeader, result.mach_headers.items),
        .mach_headers_len = result.mach_headers.items.len,
        .load_cmd_regions = slicePtr(types.LoadCommandsRegion, result.load_cmd_regions.items),
        .load_cmd_regions_len = result.load_cmd_regions.items.len,
        .load_commands = slicePtr(types.LoadCommand, result.load_commands.items),
        .load_commands_len = result.load_commands.items.len,
        .segment64_commands = slicePtr(types.Segment64Command, result.segment64_commands.items),
        .segment64_commands_len = result.segment64_commands.items.len,
        .section64_records = slicePtr(types.Section64, result.section64_records.items),
        .section64_records_len = result.section64_records.items.len,
        .symtab_commands = slicePtr(types.SymtabCommand, result.symtab_commands.items),
        .symtab_commands_len = result.symtab_commands.items.len,
        .dysymtab_commands = slicePtr(types.DysymtabCommand, result.dysymtab_commands.items),
        .dysymtab_commands_len = result.dysymtab_commands.items.len,
        .uuid_commands = slicePtr(types.UuidCommand, result.uuid_commands.items),
        .uuid_commands_len = result.uuid_commands.items.len,
        .build_version_commands = slicePtr(types.BuildVersionCommand, result.build_version_commands.items),
        .build_version_commands_len = result.build_version_commands.items.len,
        .build_tool_versions = slicePtr(types.BuildToolVersion, result.build_tool_versions.items),
        .build_tool_versions_len = result.build_tool_versions.items.len,
    };
}

// Ownership: caller receives a handle; destroy must be called to free all memory.
export fn zm_parse(path: [*:0]const u8, out_handle: *?*anyopaque) ZmStatus {
    out_handle.* = null;
    const allocator = std.heap.c_allocator;
    const path_slice = std.mem.span(path);

    var result = macho.parseFile(allocator, path_slice) catch |err| {
        return switch (err) {
            error.OutOfMemory => .OutOfMemory,
            else => .IoError,
        };
    };

    const handle = allocator.create(macho.ParseResult) catch {
        result.deinit();
        return .OutOfMemory;
    };
    handle.* = result;
    out_handle.* = @ptrCast(handle);
    return .Ok;
}

// Ownership: releases all memory associated with the parse handle.
export fn zm_destroy(handle: ?*anyopaque) void {
    if (handle == null) return;
    const allocator = std.heap.c_allocator;
    const result: *macho.ParseResult = @ptrCast(@alignCast(handle.?));
    result.deinit();
    allocator.destroy(result);
}

// Read-only view: pointers remain valid until zm_destroy is called.
export fn zm_get_view(handle: ?*anyopaque, out_view: *ZmParseView) void {
    if (handle == null) {
        out_view.* = std.mem.zeroes(ZmParseView);
        return;
    }
    const result: *macho.ParseResult = @ptrCast(@alignCast(handle.?));
    fillView(result, out_view);
}
