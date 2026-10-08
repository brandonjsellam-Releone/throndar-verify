# Rust input boundary — specification before implementation

Date: 2026-10-08. Assurance tier: Tier 1 Rust. Parent specification: THRONDAR_VERIFY_RUST_PORT_SPEC_2026-09-11.md revision 9, sections 2.1, 3.2 G3–G5, 4.1, 4.5–4.7. This bounded first slice is not a cryptographic verifier, v2 release, or replacement for the existing Action.

## Scope and invariants

1. The tv-cli library transport accepts a caller-supplied Read, consumes at most 4,000,001 bytes, and rejects more than 4,000,000 bytes before parsing. Exactly 4,000,000 bytes may succeed. It does not open files, read environment variables, or infer whether the reader is stdin. The eventual CLI must classify I/O errors according to their source as G3 requires.
2. tv-core has no I/O. Its byte-slice entrypoint independently enforces the same cap; strict UTF-8 and no leading U+FEFF BOM; RFC 8259 syntax; exactly one JSON value; no duplicate decoded object names at any nesting level; no unpaired Unicode surrogate escape; at most 64 nested containers. A root object or array counts as depth one; scalar values do not add a container level.
3. Numbers remain in the original source spelling. This stage does not round them, deserialize them into machine numbers, canonicalize them, or decide field-specific integer rules. Values such as 1e400 remain syntactically valid JSON at this stage and require later typed validation.
4. Success returns only UntrustedJson. Its private source can be borrowed explicitly as untrusted text; there is no verification status, trust anchor, signature check, signing capability, or report of verified claims. Even an authentic demo receipt remains untrusted after parsing.
5. Error display and debug output expose rule names and structural positions only. Duplicate object names and input contents are never included. Positions use array indices and object-member ordinal indices, not untrusted member names. Input document Debug is redacted.
6. The public depth bound is checked before recursive deserialization, using an iterative structural scan that ignores bracket characters inside strings. RFC syntax remains the parser's responsibility. A precheck can refuse malformed deeply nested input as TooDeep; no malformed input may succeed. Nested parsing is bounded by 64; the input cap bounds bytes but not a constant small memory footprint. Object-name sets allocate with input cardinality; no unbounded reader is buffered.
7. Existing JavaScript, fixtures, workflows, and package manifests remain unchanged and are not dependencies of this Rust library.

## Implementation plan

Create a Rust 2024 workspace with MSRV 1.90 and pinned toolchain 1.97.1. Add tv-core strict input validation and tv-cli bounded reader library. Use the specification-approved serde, serde_json (raw_value only beyond defaults), and thiserror dependencies; exact versions recorded in Cargo.toml/Cargo.lock. RawValue preserves numeric spelling; a recursive visitor rejects duplicate decoded names and validates every string. There is no handmade JSON number decoder or cryptographic primitive. Add supply-chain deny policy and dependency justifications.

Implementation clarification: the reader byte bound is not a deadline. A blocking reader or one that returns Interrupted forever can take unbounded wall time. Source acquisition and timeouts belong to the eventual CLI or service. The core accepts syntactically valid JSON scalar roots at G5; G6/G8 must reject unsupported artifact shapes later. This stage cannot be used as an artifact acceptance gate.

## Tests before implementation

First run a compile-valid reject-all scaffold against tests and record assertion failures, including valid inputs, exact size, Unicode, raw numbers, depth boundaries, and successful short/chunked readers. After implementation, test invalid UTF-8, BOM, malformed/trailing JSON, duplicate names at multiple depths (including escaped-equivalent names), lone surrogate in values and names, valid pairs, depth 64/65 and extreme nesting, braces inside strings, multibyte byte-cap accounting, bounded reader consumption, interrupted/failed readers, I/O error redaction, and untrusted Debug redaction. Add assertion-level mutation evidence for cap, duplicate, depth, surrogate, and single-document controls; compilation failures or timeouts do not count as kills.

## Explicitly unfinished

G1/G2 CLI/source enumeration, G6 kind ambiguity/classification, G7 field cardinality caps, G8 typed schema/binary decoding, canonicalization, cryptography/KATs, trust pins, origin policy, reports, signed formats, release binaries, Action migration, full-spec fuzz/Miri/release-target gates, and production integration. No Lean is authored because this is a parser boundary, not a newly implemented protocol invariant, and proof authoring was not delegated. Future schema verification must consume the untrusted source without bypassing this boundary.

## Security impact

This slice adds strict acceptance checks for untrusted input. It can reject malformed or ambiguous JSON syntax, but cannot establish authenticity, authorization, safe content, semantic equivalence, or any platform security guarantee. The test evidence and limitations must accompany review; a passed parser test cannot certify the website, signer, or verifier release.
