pub const ByteRange = extern struct {
    offset: u64,
    size: u64,
};

pub const EntityKind = enum(u8) {
    File = 0,
    FatHeader = 1,
    FatArchEntry = 2,
    Slice = 3,
    MachHeader = 4,
    LoadCommandsRegion = 5,
    LoadCommand = 6,
};

pub const EntityId = extern struct {
    index: u32,
};

pub const Entity = extern struct {
    kind: EntityKind,
    range: ByteRange,
};

pub const DiagnosticCode = enum(u8) {
    file_open_failed = 1,
    file_stat_failed = 2,
    invalid_magic = 3,
    fat_header_truncated = 4,
    fat_arch_truncated = 5,
    slice_out_of_bounds = 6,
    invalid_mach_magic = 7,
    mach_header_truncated = 8,
    mach_header_out_of_bounds = 9,
    load_cmd_region_out_of_bounds = 10,
    load_cmd_region_truncated = 11,
    load_cmd_header_truncated = 12,
    load_cmd_malformed_size = 13,
    load_cmd_out_of_bounds = 14,
};

pub const DiagnosticSeverity = enum(u8) {
    Error = 1,
    Warning = 2,
};

pub const Diagnostic = extern struct {
    severity: DiagnosticSeverity,
    code: DiagnosticCode,
    range: ByteRange,
};

pub const Endianness = enum(u8) {
    big = 0,
    little = 1,
};

pub const FatHeader = extern struct {
    magic: u32,
    nfat_arch: u32,
    is_64: u8,
    endian: Endianness,
    entity: EntityId,
};

pub const FatArchEntry = extern struct {
    cputype: u32,
    cpusubtype: u32,
    offset: u64,
    size: u64,
    alignment: u32,
    reserved: u32,
    entity: EntityId,
    slice: EntityId,
};

pub const Containment = extern struct {
    kind: ContainmentKind,
    parent: EntityId,
    child: EntityId,
};

pub const ContainmentKind = enum(u8) {
    Owns = 0,
    Describes = 1,
};

pub const MachHeader = extern struct {
    magic: u32,
    cputype: u32,
    cpusubtype: u32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: u32,
    is_64: u8,
    endian: Endianness,
    entity: EntityId,
};

pub const LoadCommandsRegion = extern struct {
    sizeofcmds: u32,
    entity: EntityId,
};

pub const LoadCommand = extern struct {
    cmd: u32,
    cmdsize: u32,
    entity: EntityId,
};
