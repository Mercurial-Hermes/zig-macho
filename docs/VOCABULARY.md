# zig-macho — Vocabulary

This document defines the **initial shared vocabulary** used throughout the zig-macho codebase, documentation, tests, and discussions.

The goal is not exhaustiveness, but **precision and alignment**.

Terms defined here are intended to:
- Match real Mach-O / Apple platform concepts
- Avoid overloaded or ambiguous language
- Remain stable as the project grows
- Support future consumers (SwiftUI, debuggers, analysers)

This vocabulary will evolve. Changes should be deliberate and discussed.

---

## Core Concepts

### Binary
A file on disk containing executable or object code in a known format.

In zig-macho, this almost always refers to a **Mach-O binary**, either thin or FAT.

---

### File
The raw byte sequence as read from disk.

- Has a size
- Has a single contiguous byte range: `[0, file_size)`
- Is the root of all structure

---

### Byte Range
A half-open interval describing a contiguous region of the file:

```text
[offset, offset + size)
```


Properties:

- Always expressed in file offsets
- Must be bounds-checked against file size
- If something occupies bytes, it has a range

---

### Entity

Any structured element parsed from the file that:

- Occupies bytes
- Has a range
- Has a clear role in the file format

Examples:

- FAT header
- Slice
- Mach-O header
- Load command
- Segment
- Section

---

### Identity

A stable identifier assigned to an entity **within a single parse**.

- Used for referential stability
- Deterministic across runs for the same input
- Typically index-based, not globally unique

Identity is not a hash and not intended for persistence across files.

---

## FAT / Universal Binary

### FAT Binary

A Mach-O container that holds multiple architecture-specific slices.

Also known as:

- Universal binary
- Multi-architecture binary

---

### FAT Header

The top-level header of a FAT binary.

Defines:

- Magic value
- Number of architecture entries

Occupies a fixed byte range at the start of the file.

---

### FAT Architecture Entry

A record describing one slice inside a FAT binary.

Contains:

- CPU type
- CPU subtype
- Slice file offset
- Slice size
- Alignment

The entry itself has a byte range distinct from the slice payload it describes.

---

### Slice

A contiguous region of the file representing a **single Mach-O image**.

- Identified by CPU type and subtype
- Has a payload byte range
- Contains exactly one Mach-O header

In a thin binary, the entire file is treated as a single slice.

---

## Mach-O Image

### Mach-O Image

A single architecture-specific Mach-O binary.

Contained either:

- Directly in a file (thin binary)
- Inside a slice of a FAT binary

---

### Mach-O Header

The header at the start of a Mach-O image.

Defines:

- 32-bit vs 64-bit format
- CPU type / subtype
- File type
- Number of load commands
- Size of load commands region
- Flags

The header itself has a precise byte range.

---

### Load Commands Region

The contiguous block of bytes immediately following the Mach-O header that contains all load commands.

- Size is given by the Mach-O header
- Commands are stored sequentially
- Order is meaningful and preserved

---

## Load Commands

### Load Command

A typed record within the load commands region.

Each load command has:

- A command type (`cmd`)
- A command size (`cmdsize`)
- A precise byte range
- Typed fields (for known commands)

Unknown or unsupported commands are still represented structurally.

---

### Known Load Command

A load command whose structure is understood and parsed into typed fields.

Example:

- `LC_SEGMENT_64`

---

### Unknown Load Command

A load command whose `cmd` is not recognized or not yet implemented.

Still exposes:

- Command type
- Command size
- Byte range
- Raw bytes (if needed)

Unknown does not mean ignored.

---

## Segments and Sections

### Segment

A logical grouping of sections described by a segment load command.

Properties include:

- Virtual memory address and size
- File offset and size
- Protection flags
- Flags

Segments describe intended VM layout but are still part of file structure.

---

### Section

A subdivision of a segment.

Properties include:

- Section name
- Segment name
- Address and size
- File offset
- Alignment
- Flags

Sections may or may not correspond to contiguous file ranges, depending on layout.

---

## Ordering and Structure

### Order

The sequence in which entities appear in the file.

Order is:

- Preserved exactly
- Considered data
- Never rearranged for convenience

---

### Containment

An explicit parent–child relationship between entities.

Examples:

- File contains slices
- Slice contains a Mach-O image
- Mach-O image contains load commands
- Segment contains sections

Containment is expressed explicitly, not inferred.

---

## Diagnostics

### Diagnostic

A structured report of an issue encountered during parsing.

Includes:

- Severity (warning or error)
- Byte range associated with the issue
- Stable diagnostic code
- Optional metadata

Diagnostics are data, not just log messages.

---

### Recoverable Error

An error that violates expectations but still allows parsing to continue safely.

Example:

- Unexpected command size
- Section range extending past file bounds (clamped and flagged)

---

### Fatal Error

An error that prevents further safe parsing.

Example:

- Invalid magic
- Truncated file where structure cannot be trusted

---

## Interpretation vs Description

### Description

Faithfully reporting what the file declares.

This is zig-macho’s responsibility.

---

### Interpretation

Assigning meaning, intent, or runtime behavior to declared structure.

This is explicitly **out of scope** for zig-macho and left to consumers.

---

## Consumers

### Consumer

Any tool or application that uses zig-macho’s output.

Examples:

- SwiftUI visualisers
- CLI inspection tools
- Debuggers
- Educational tooling

Consumers decide how to _present_ or _interpret_ structure.
