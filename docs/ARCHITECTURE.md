# ARCHITECTURE — zig-macho

This document describes the current structure of zig-macho as implemented today.
It is descriptive, not aspirational.

## Purpose

zig-macho is a learning-first systems library that describes Mach-O binaries as
structured, byte-range entities. It answers:

"What structure exists in this Mach-O file, and where does it live in bytes?"

It does not interpret runtime meaning, implement loader behavior, or present UI.

## Core Model

The canonical parse result is a set of explicit tables plus a containment graph:

- Entity table: ordered list of structural entities with byte ranges.
- Metadata tables: typed records for specific entity kinds (FAT, MachHeader, load commands, typed commands, sections).
- Containment graph: explicit parent/child relationships with a semantic kind.
- Diagnostics: structured list of issues with severity and byte ranges.

All entities and diagnostics are range-first and deterministic.

## Entity Kinds (Current)

### File
- Represents: the full file as a byte space.
- Range: `[0, file_size)`.
- Containment: owns FAT headers, FAT arch entries, and slices.

### FatHeader
- Represents: the top-level FAT header in a universal binary.
- Range: fixed header bytes at file start.
- Containment: owned by File.

### FatArchEntry
- Represents: one FAT architecture entry describing a slice.
- Range: the entry record inside the FAT table.
- Containment: owned by File; describes its corresponding Slice.

### Slice
- Represents: a contiguous Mach-O image inside the file.
- Range: offset and size from FAT entry, or whole file for thin binaries.
- Containment: owned by File; owns its MachHeader.

### MachHeader
- Represents: the Mach-O header at the start of a slice.
- Range: header size (32-bit or 64-bit) starting at slice offset.
- Containment: owned by its Slice.

### LoadCommandsRegion
- Represents: the contiguous load command region following a MachHeader.
- Range: `[header_end, header_end + sizeofcmds)`.
- Containment: owned by its MachHeader; owns LoadCommand and LoadCommandPadding.

### LoadCommand
- Represents: one load command record in the load command region.
- Range: `[offset, offset + cmdsize)`.
- Containment: owned by LoadCommandsRegion; may own a typed command entity.

### LoadCommandPadding
- Represents: unclaimed bytes inside a load command or load command region.
- Range: the exact padding span.
- Containment: owned by LoadCommandsRegion or by a LoadCommand.

### Segment64Command
- Represents: the fixed LC_SEGMENT_64 header structure.
- Range: fixed-size header portion of the command.
- Containment: owned by its LoadCommand; owns Section64 records.

### Section64
- Represents: one fixed-layout section record in LC_SEGMENT_64.
- Range: the section record bytes in the command.
- Containment: owned by its Segment64Command.

### SymtabCommand
- Represents: the fixed LC_SYMTAB structure.
- Range: fixed-size header portion of the command.
- Containment: owned by its LoadCommand.

### DysymtabCommand
- Represents: the fixed LC_DYSYMTAB structure.
- Range: fixed-size header portion of the command.
- Containment: owned by its LoadCommand.

### UuidCommand
- Represents: the fixed LC_UUID structure.
- Range: fixed-size header portion of the command.
- Containment: owned by its LoadCommand.

### BuildVersionCommand
- Represents: the fixed LC_BUILD_VERSION structure.
- Range: fixed-size header portion of the command.
- Containment: owned by its LoadCommand; owns BuildToolVersion records.

### BuildToolVersion
- Represents: one tool/version record in LC_BUILD_VERSION.
- Range: the tool record bytes in the command.
- Containment: owned by its BuildVersionCommand.

## Containment Semantics

Containment edges are explicitly typed:

- Owns: structural containment (e.g., File -> Slice, Slice -> MachHeader, MachHeader -> LoadCommandsRegion, LoadCommand -> Segment64Command).
- Describes: metadata relationship (e.g., FatArchEntry -> Slice).

These semantics do not add interpretation; they clarify structural roles.

## Parsing Phases (Current)

1. File open + File entity emission
2. Magic detection at file start
3. FAT vs thin classification
4. Slice emission (from FAT entries or whole file)
5. Mach-O header parsing at each slice start
6. Load command region parsing and generic LoadCommand emission
7. Typed load command refinement (segment64, symtab, dysymtab, uuid, build_version)
8. Section and tool record emission within typed commands

## Determinism & Stability

- Entities are emitted in file order; order is treated as data.
- Entity identities are stable indexes within a single parse.
- No hidden global state; all ownership is explicit in ParseResult.

## Consumer Contract

zig-macho emits one canonical structural truth of a file.
Consumers build projections from this data without altering structure.
SwiftUI is a consumer and never a dependency.
