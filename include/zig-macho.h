#ifndef ZIG_MACHO_H
#define ZIG_MACHO_H

#include <stdint.h>
#include <stddef.h>

typedef uint8_t EntityKind;
enum {
    EntityKind_File = 0,
    EntityKind_FatHeader = 1,
    EntityKind_FatArchEntry = 2,
    EntityKind_Slice = 3,
    EntityKind_MachHeader = 4,
    EntityKind_LoadCommandsRegion = 5,
    EntityKind_LoadCommand = 6,
    EntityKind_LoadCommandPadding = 7,
    EntityKind_Segment64Command = 8,
    EntityKind_Section64 = 9,
    EntityKind_SymtabCommand = 10,
    EntityKind_DysymtabCommand = 11,
    EntityKind_UuidCommand = 12,
    EntityKind_BuildVersionCommand = 13,
    EntityKind_BuildToolVersion = 14,
    EntityKind_Gap = 15,
};

typedef struct ByteRange {
    uint64_t offset;
    uint64_t size;
} ByteRange;

typedef uint8_t DiagnosticCode;
enum {
    DiagnosticCode_file_open_failed = 1,
    DiagnosticCode_file_stat_failed = 2,
    DiagnosticCode_invalid_magic = 3,
    DiagnosticCode_fat_header_truncated = 4,
    DiagnosticCode_fat_arch_truncated = 5,
    DiagnosticCode_slice_out_of_bounds = 6,
    DiagnosticCode_invalid_mach_magic = 7,
    DiagnosticCode_mach_header_truncated = 8,
    DiagnosticCode_mach_header_out_of_bounds = 9,
    DiagnosticCode_load_cmd_region_out_of_bounds = 10,
    DiagnosticCode_load_cmd_region_truncated = 11,
    DiagnosticCode_load_cmd_header_truncated = 12,
    DiagnosticCode_load_cmd_malformed_size = 13,
    DiagnosticCode_load_cmd_out_of_bounds = 14,
    DiagnosticCode_load_cmd_typed_truncated = 15,
    DiagnosticCode_load_cmd_sections_truncated = 16,
    DiagnosticCode_load_cmd_tools_truncated = 17,
};

typedef uint8_t DiagnosticSeverity;
enum {
    DiagnosticSeverity_Error = 1,
    DiagnosticSeverity_Warning = 2,
};

typedef uint8_t Endianness;
enum {
    Endianness_big = 0,
    Endianness_little = 1,
};

typedef uint8_t ContainmentKind;
enum {
    ContainmentKind_Owns = 0,
    ContainmentKind_Describes = 1,
};

typedef struct EntityId {
    uint32_t index;
} EntityId;

typedef struct Entity {
    EntityKind kind;
    ByteRange range;
} Entity;

typedef struct Diagnostic {
    DiagnosticSeverity severity;
    DiagnosticCode code;
    ByteRange range;
} Diagnostic;

typedef struct FatHeader {
    uint32_t magic;
    uint32_t nfat_arch;
    uint8_t is_64;
    Endianness endian;
    EntityId entity;
} FatHeader;

typedef struct FatArchEntry {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint64_t offset;
    uint64_t size;
    uint32_t alignment;
    uint32_t reserved;
    EntityId entity;
    EntityId slice;
} FatArchEntry;

typedef struct Containment {
    ContainmentKind kind;
    EntityId parent;
    EntityId child;
} Containment;

typedef struct MachHeader {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
    uint8_t is_64;
    Endianness endian;
    EntityId entity;
} MachHeader;

typedef struct LoadCommandsRegion {
    uint32_t sizeofcmds;
    EntityId entity;
} LoadCommandsRegion;

typedef struct LoadCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    EntityId entity;
} LoadCommand;

typedef struct Segment64Command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint8_t segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
    ByteRange cmd_range;
    ByteRange cmdsize_range;
    ByteRange segname_range;
    ByteRange vmaddr_range;
    ByteRange vmsize_range;
    ByteRange fileoff_range;
    ByteRange filesize_range;
    ByteRange maxprot_range;
    ByteRange initprot_range;
    ByteRange nsects_range;
    ByteRange flags_range;
    EntityId entity;
} Segment64Command;

typedef struct Section64 {
    uint8_t sectname[16];
    uint8_t segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t alignment;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
    ByteRange sectname_range;
    ByteRange segname_range;
    ByteRange addr_range;
    ByteRange size_range;
    ByteRange offset_range;
    ByteRange alignment_range;
    ByteRange reloff_range;
    ByteRange nreloc_range;
    ByteRange flags_range;
    ByteRange reserved1_range;
    ByteRange reserved2_range;
    ByteRange reserved3_range;
    EntityId entity;
} Section64;

typedef struct SymtabCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
    ByteRange cmd_range;
    ByteRange cmdsize_range;
    ByteRange symoff_range;
    ByteRange nsyms_range;
    ByteRange stroff_range;
    ByteRange strsize_range;
    EntityId entity;
} SymtabCommand;

typedef struct DysymtabCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t ilocalsym;
    uint32_t nlocalsym;
    uint32_t iextdefsym;
    uint32_t nextdefsym;
    uint32_t iundefsym;
    uint32_t nundefsym;
    uint32_t tocoff;
    uint32_t ntoc;
    uint32_t modtaboff;
    uint32_t nmodtab;
    uint32_t extrefsymoff;
    uint32_t nextrefsyms;
    uint32_t indirectsymoff;
    uint32_t nindirectsyms;
    uint32_t extreloff;
    uint32_t nextrel;
    uint32_t locreloff;
    uint32_t nlocrel;
    ByteRange cmd_range;
    ByteRange cmdsize_range;
    ByteRange ilocalsym_range;
    ByteRange nlocalsym_range;
    ByteRange iextdefsym_range;
    ByteRange nextdefsym_range;
    ByteRange iundefsym_range;
    ByteRange nundefsym_range;
    ByteRange tocoff_range;
    ByteRange ntoc_range;
    ByteRange modtaboff_range;
    ByteRange nmodtab_range;
    ByteRange extrefsymoff_range;
    ByteRange nextrefsyms_range;
    ByteRange indirectsymoff_range;
    ByteRange nindirectsyms_range;
    ByteRange extreloff_range;
    ByteRange nextrel_range;
    ByteRange locreloff_range;
    ByteRange nlocrel_range;
    EntityId entity;
} DysymtabCommand;

typedef struct UuidCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    uint8_t uuid[16];
    ByteRange cmd_range;
    ByteRange cmdsize_range;
    ByteRange uuid_range;
    EntityId entity;
} UuidCommand;

typedef struct BuildVersionCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t platform;
    uint32_t minos;
    uint32_t sdk;
    uint32_t ntools;
    ByteRange cmd_range;
    ByteRange cmdsize_range;
    ByteRange platform_range;
    ByteRange minos_range;
    ByteRange sdk_range;
    ByteRange ntools_range;
    EntityId entity;
} BuildVersionCommand;

typedef struct BuildToolVersion {
    uint32_t tool;
    uint32_t version;
    ByteRange tool_range;
    ByteRange version_range;
    EntityId entity;
} BuildToolVersion;

typedef enum ZmStatus {
    ZmStatus_Ok = 0,
    ZmStatus_IoError = 1,
    ZmStatus_OutOfMemory = 2,
} ZmStatus;

typedef struct ZmParseView {
    uint64_t file_size;

    const Entity *entities;
    size_t entities_len;

    const Diagnostic *diagnostics;
    size_t diagnostics_len;

    const Containment *containments;
    size_t containments_len;

    const FatHeader *fat_headers;
    size_t fat_headers_len;

    const FatArchEntry *fat_arch_entries;
    size_t fat_arch_entries_len;

    const MachHeader *mach_headers;
    size_t mach_headers_len;

    const LoadCommandsRegion *load_cmd_regions;
    size_t load_cmd_regions_len;

    const LoadCommand *load_commands;
    size_t load_commands_len;

    const Segment64Command *segment64_commands;
    size_t segment64_commands_len;

    const Section64 *section64_records;
    size_t section64_records_len;

    const SymtabCommand *symtab_commands;
    size_t symtab_commands_len;

    const DysymtabCommand *dysymtab_commands;
    size_t dysymtab_commands_len;

    const UuidCommand *uuid_commands;
    size_t uuid_commands_len;

    const BuildVersionCommand *build_version_commands;
    size_t build_version_commands_len;

    const BuildToolVersion *build_tool_versions;
    size_t build_tool_versions_len;
} ZmParseView;

/* Ownership: zm_parse allocates a handle; caller must release with zm_destroy. */
ZmStatus zm_parse(const char *path, void **out_handle);

/* Ownership: all memory associated with the handle is released. */
void zm_destroy(void *handle);

/* Read-only view: pointers are valid until zm_destroy; data must not be mutated. */
void zm_get_view(void *handle, ZmParseView *out_view);

#endif
