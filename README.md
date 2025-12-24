# zig-macho

**zig-macho** is a foundational Zig library for parsing and *describing* Mach-O binaries on Apple platforms.

It is a **learning-first systems project** with the explicit goal of developing deep, durable understanding of macOS internals — knowledge that will later feed directly into the design and implementation of **dipole-dbg**, an experimental next-generation debugger for Apple Silicon.

zig-macho is the first in a planned *suite* of low-level introspection libraries, written in Zig, that probe macOS from the bottom up.

---

## Purpose

zig-macho exists to answer one question precisely:

> *What structure exists in this Mach-O file, and where does it live?*

It does **not** attempt to interpret runtime meaning, execution behavior, or higher-level semantics. It is an *instrument*, not an opinionated tool.

The library is designed to be:

- **Low-level, precise, and reusable**
- **Independent of any UI, runtime, or application**
- **Deterministic and testable**
- **Safe by construction (strict bounds checking)**
- **Consumable across language boundaries**

Planned consumers include:

- Zig-based tooling
- C programs (via a stable C ABI)
- Swift / SwiftUI applications (educational and exploratory)
- Debuggers, analysers, and research tools

Swift is always a **consumer**, never a dependency.

---

## Learning Context

This project is intentionally structured as a *learning probe* into macOS:

- Mach-O layout and invariants
- Apple ABI realities
- File vs VM address spaces
- Loader-facing binary structure
- What the kernel and `dyld` expect to see (without implementing them)

Design decisions prioritize **clarity, explicitness, and correctness** over speed of implementation.

---

## Scope (Initial)

zig-macho is responsible for **describing what is present in a Mach-O file**, not what it means at runtime.

### In Scope

- Read-only file I/O
- FAT / universal binary detection
- Mach-O header parsing
  - 32-bit and 64-bit
  - Initial focus on `arm64`
- Slice enumeration
  - CPU type / subtype
  - Offsets and sizes
- Load command parsing (typed, ordered)
- Segment and section layout
- Exact byte ranges for all entities
- Safe bounds checking
- Deterministic output suitable for visualization

### Explicitly Out of Scope (for now)

- `dyld` behavior
- Symbolication
- Objective-C or Swift runtime semantics
- Code-signing validation
- Execution, relocation, or VM mapping
- Any UI or presentation logic

These concerns are intentionally deferred to higher-level libraries and applications.

---

## Design Principles

### 1. Pure Description, Not Interpretation

zig-macho reports **what exists**, not **what it means**.

No inference, policy, or runtime assumptions are embedded in the parsing layer.

---

### 2. Structured Over Byte-Oriented

Bytes are parsed **once** into typed structures.

Downstream consumers work with structured data — not magic numbers, offsets, or ad-hoc parsing logic.

---

### 3. Range-First Design

Every meaningful entity exposes an explicit byte range:

- File
- FAT headers and entries
- Slices
- Mach-O headers
- Load commands
- Segments
- Sections

If something occupies bytes, it has a range.

This enables spatial reasoning, deterministic UI, and future GPU-backed visualization.

---

### 4. Order Is Sacred

If the file encodes an order, zig-macho preserves it:

- FAT architecture order
- Load command order
- Section order within segments

No sorting.  
No regrouping.  
Order is data.

---

### 5. Explicit Relationships

Containment and relationships are expressed explicitly:

- File → FAT → slices
- Slice → Mach-O image
- Image → load commands
- Segments → sections

Consumers never need to infer structure from offsets alone.

---

### 6. No Hidden Global State

All state is:

- Explicit
- Owned
- Passed through well-defined interfaces

No ambient context. No global configuration.

---

### 7. Stable, Minimal C ABI

zig-macho exposes a stable, minimal C ABI to support Swift and other consumers:

- Fixed-layout `extern` structs
- No Zig-specific types cross the boundary
- Explicit lifetime management
- No callbacks or hidden iteration

ABI stability is treated as a first-class constraint.

---

## Designing for a Glass UI (Without Becoming UI)

zig-macho is intentionally designed to *enable* a future SwiftUI “glass instrument panel” without embedding UI concerns.

The rule is simple:

> **zig-macho describes structure; the UI animates perception.**

zig-macho never:
- Groups “for convenience”
- Guesses importance
- Hides boring details
- Formats for display

zig-macho always:
- Exposes true boundaries
- Preserves real order
- Emits exact ranges
- Expresses relationships explicitly

This discipline ensures that visual consumers remain honest reflections of reality.

---

## Toolchain

- **Language:** Zig
- **Pinned Zig Version:** 0.14.x
- **Platforms:** macOS (Apple Silicon focus)

The Zig version is pinned intentionally to reduce churn while learning fundamentals.

---

## Project Status

Early exploratory development.

Initial milestones focus on:

1. File open + magic detection
2. FAT vs thin Mach-O identification
3. Slice enumeration with exact ranges
4. Deterministic, testable output
5. Clean ABI surfaces for future SwiftUI consumption

---

## Long-Term Vision

zig-macho is the first building block in a broader effort to:

- Reclaim understanding of macOS internals
- Build honest, inspectable tooling
- Lay the groundwork for **dipole-dbg**
- Explore debugger design for Apple Silicon from first principles

This is a long game. Precision comes first.

---

## License

GNU AFFERO GENERAL PUBLIC LICENSE
Version 3, 19 November 2007
