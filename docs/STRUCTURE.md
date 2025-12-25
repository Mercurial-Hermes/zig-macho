# zig-macho — Structural Contract

## Purpose

`zig-macho` is a **structural instrumentation library** for Mach-O binaries.

It does not interpret, explain, normalize, or simplify Mach-O files.

Its sole responsibility is to emit a **faithful, ordered, byte-accurate structural model** of a real macOS binary, suitable for downstream rendering and inspection without inference.

This document defines the **non-negotiable structural contract** that all current and future development must uphold.

---

## Core Principle

> **Every byte in the file must belong to an explicit structural entity.**

If a downstream consumer must guess where a byte belongs,
`zig-macho` is incomplete.

---

## Structural Model Overview

`zig-macho` emits a single immutable structural tree.

### Structural Entities

Every emitted entity has:

* A **kind**
* A **byte range** `[start, end)`
* A **stable structural identity**
* A **parent entity** (except the root)
* A deterministic **position among siblings**

Entities represent *presence*, not meaning.

---

## Root and Range Completeness

### File Root

* A single root entity represents the entire file:

  * Range: `[0 .. file_size)`
* All other entities must be contained within this root.

### Range Completeness Invariant

The union of all emitted entity ranges must cover the entire file range.

* No orphan bytes
* No implicit regions
* No unaccounted padding

If a byte does not belong to a semantic structure, it must still belong to a **structural entity**.

---

## Padding, Gaps, and Slack

Bytes that exist only due to:

* alignment
* padding
* unused space
* malformed or truncated structure

must be emitted explicitly as structural entities.

Examples:

* `Padding`
* `Gap`
* `AlignmentSlack` (if distinguished)

These entities:

* Have precise byte ranges
* Participate in ordering and containment
* Carry no semantic meaning
* Are not diagnostics

Padding is structure, not error.

---

## Ordering Guarantees

All entities are emitted in **deterministic byte order**.

* Sibling entities are ordered strictly by file offset
* Ordering is stable across parses of the same binary
* Ordering does not depend on semantic interpretation

Ordering exists to support rendering, traversal, and animation.

---

## Identity Stability

Structural identities are derived from:

* Parent identity
* Entity kind
* Ordinal position among siblings after structural closure

Identity stability is guaranteed starting in v0.0.6.

Prior to v0.0.6, entity ordering may change as structural closure logic is introduced.

---

## Containment Rules

Containment reflects **byte ownership**, not conceptual meaning.

* An entity is contained by the smallest enclosing entity that owns its range
* Containment must never be inferred downstream
* All containment relationships must be explicit

No entity may overlap another unless:

* the overlap is explicitly modeled
* or one strictly contains the other

---

## Diagnostics as Structure

Diagnostics are not side-band metadata.

When possible, diagnostics must be emitted as **structural nodes**:

* Attached to the entity they describe
* Ordered relative to surrounding structure
* Renderable by consumers

Malformed binaries must still yield a renderable structure.

Failure to parse is not failure to structure.

---

## Cross-Reference Edges (Non-Semantic)

`zig-macho` may emit cross-reference edges when they are:

* explicitly encoded in the binary
* structurally verifiable

Examples:

* Load command → referenced region
* Segment → section ranges

Cross-references must:

* never imply meaning
* never group entities
* never reparent structure

They exist solely to express relationships already present in the file.

---

## Forbidden Behaviors

`zig-macho` must never:

* Group entities by semantic meaning
* Reorder entities for convenience
* Hide or discard padding
* Collapse structure for readability
* Invent entities to “clean up” malformed binaries
* Emit consumer-facing abstractions

Awkward structure is correct structure.

---

## Consumer Responsibility Boundary

Downstream consumers (UI, C ABI, Swift):

* Must treat emitted structure as immutable truth
* Must not infer or repair structure
* May navigate, render, and focus subtrees
* Must never reshape the tree

If a consumer must guess, the fault lies in `zig-macho`.

---

## North Star

`zig-macho` is not a developer parser.

It is a **measurement instrument** for tools that make macOS system structure visible.

Truth precedes usability.
Structure precedes meaning.
Rendering follows emission.
