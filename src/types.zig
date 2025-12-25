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
    LoadCommandPadding = 7,
    Segment64Command = 8,
    Section64 = 9,
    SymtabCommand = 10,
    DysymtabCommand = 11,
    UuidCommand = 12,
    BuildVersionCommand = 13,
    BuildToolVersion = 14,
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
    load_cmd_typed_truncated = 15,
    load_cmd_sections_truncated = 16,
    load_cmd_tools_truncated = 17,
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

pub const Segment64Command = extern struct {
    cmd: u32,
    cmdsize: u32,
    segname: [16]u8,
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    nsects: u32,
    flags: u32,
    cmd_range: ByteRange,
    cmdsize_range: ByteRange,
    segname_range: ByteRange,
    vmaddr_range: ByteRange,
    vmsize_range: ByteRange,
    fileoff_range: ByteRange,
    filesize_range: ByteRange,
    maxprot_range: ByteRange,
    initprot_range: ByteRange,
    nsects_range: ByteRange,
    flags_range: ByteRange,
    entity: EntityId,
};

pub const Section64 = extern struct {
    sectname: [16]u8,
    segname: [16]u8,
    addr: u64,
    size: u64,
    offset: u32,
    alignment: u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    reserved3: u32,
    sectname_range: ByteRange,
    segname_range: ByteRange,
    addr_range: ByteRange,
    size_range: ByteRange,
    offset_range: ByteRange,
    alignment_range: ByteRange,
    reloff_range: ByteRange,
    nreloc_range: ByteRange,
    flags_range: ByteRange,
    reserved1_range: ByteRange,
    reserved2_range: ByteRange,
    reserved3_range: ByteRange,
    entity: EntityId,
};

pub const SymtabCommand = extern struct {
    cmd: u32,
    cmdsize: u32,
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
    cmd_range: ByteRange,
    cmdsize_range: ByteRange,
    symoff_range: ByteRange,
    nsyms_range: ByteRange,
    stroff_range: ByteRange,
    strsize_range: ByteRange,
    entity: EntityId,
};

pub const DysymtabCommand = extern struct {
    cmd: u32,
    cmdsize: u32,
    ilocalsym: u32,
    nlocalsym: u32,
    iextdefsym: u32,
    nextdefsym: u32,
    iundefsym: u32,
    nundefsym: u32,
    tocoff: u32,
    ntoc: u32,
    modtaboff: u32,
    nmodtab: u32,
    extrefsymoff: u32,
    nextrefsyms: u32,
    indirectsymoff: u32,
    nindirectsyms: u32,
    extreloff: u32,
    nextrel: u32,
    locreloff: u32,
    nlocrel: u32,
    cmd_range: ByteRange,
    cmdsize_range: ByteRange,
    ilocalsym_range: ByteRange,
    nlocalsym_range: ByteRange,
    iextdefsym_range: ByteRange,
    nextdefsym_range: ByteRange,
    iundefsym_range: ByteRange,
    nundefsym_range: ByteRange,
    tocoff_range: ByteRange,
    ntoc_range: ByteRange,
    modtaboff_range: ByteRange,
    nmodtab_range: ByteRange,
    extrefsymoff_range: ByteRange,
    nextrefsyms_range: ByteRange,
    indirectsymoff_range: ByteRange,
    nindirectsyms_range: ByteRange,
    extreloff_range: ByteRange,
    nextrel_range: ByteRange,
    locreloff_range: ByteRange,
    nlocrel_range: ByteRange,
    entity: EntityId,
};

pub const UuidCommand = extern struct {
    cmd: u32,
    cmdsize: u32,
    uuid: [16]u8,
    cmd_range: ByteRange,
    cmdsize_range: ByteRange,
    uuid_range: ByteRange,
    entity: EntityId,
};

pub const BuildVersionCommand = extern struct {
    cmd: u32,
    cmdsize: u32,
    platform: u32,
    minos: u32,
    sdk: u32,
    ntools: u32,
    cmd_range: ByteRange,
    cmdsize_range: ByteRange,
    platform_range: ByteRange,
    minos_range: ByteRange,
    sdk_range: ByteRange,
    ntools_range: ByteRange,
    entity: EntityId,
};

pub const BuildToolVersion = extern struct {
    tool: u32,
    version: u32,
    tool_range: ByteRange,
    version_range: ByteRange,
    entity: EntityId,
};
