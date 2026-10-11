# Rust input boundary validation — 2026-10-08

This record covers only the [G3–G5 input foundation](rust-input-boundary.md), not cryptographic verification or the existing JavaScript Action. All Rust execution took place in an isolated Linux audit environment with no Windows mounts, interop, credentials, or network during compilation/tests.

The compile-valid reject-all scaffold failed 17 tests before implementation. The final suite passes 37 tests: 20 implementation tests and 17 independently authored adversary tests. The independent corpus includes all 2,048 surrogate code points in both JSON-name and value positions, all 256 single bytes, escaped-equivalent names, exact depth and byte boundaries, large number lexemes, and finite/infinite reader cases.

| Check | Result |
|---|---|
| `cargo test --workspace --all-targets --locked -- --show-output` | 37 passed, none ignored |
| `cargo +1.90.0 test --workspace --all-targets --locked -- --show-output` | 37 passed on declared MSRV |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | Passed |
| `cargo audit` | Passed; no advisory suppression |
| `cargo deny --locked check` | Advisories, bans, licenses, and sources passed |
| Miri | Not run: component unavailable in the audit VM |
| Crypto KATs, C sanitizers, Lean, TEAL | Not applicable to this no-crypto parser slice; later applicable work still requires them |

## Mutation evidence and its limits

The complete unfiltered cargo-mutants 27.1.0 run generated 25 mutants. Its unmutated baseline passed. Final result: **21 caught by failing named tests, 2 missed, 2 unviable, no timeout**. The raw command exits 1 because two mutants remain missed; this is not described as a perfect score.

The first run exposed one coverage gap: deleting the closing-delimiter decrement wrongly rejects more than 64 shallow sibling containers, although their nesting remains small. The added `many_shallow_siblings_do_not_accumulate_nesting_depth` positive test now fails for that mutant. This repaired test coverage; the implementation already handled those inputs correctly.

The two remaining missed mutants delete formatter output:

- An empty `UntrustedJson::Debug` still discloses no content. The contract does not promise exact or nonempty debug wording.
- An empty private `Visitor::expecting` diagnostic does not affect acceptance or public error classification; the underlying serde diagnostic is discarded.

An independent adversary reviewed both as equivalent with respect to this slice's acceptance/redaction contract. They remain recorded as missed. The two unviable mutants attempt `Ok(Default::default())`; `UntrustedJson` intentionally has no `Default` constructor. Compilation failures are not counted as enforcement evidence.

Two additional manual Rust source mutations were isolated, compiled, tested, and restored byte-for-byte:

| Mutation | Named test failure |
|---|---|
| Remove `Read::take(4_000_001)` | `reader_consumes_at_most_cap_plus_one`: consumed 4,020,000 instead of 4,000,001 bytes |
| Deserialize one prefix without requiring end of input | `exactly_one_complete_document_is_required`: accepted a multiple-document input instead of `JsonSyntax` |

The reader mutant ran only the finite-reader test, so a timeout could not stand in for a failed bound assertion. No Python mutation runner was authored or used. The original library source SHA-256 values before and after the manual mutations were:

- `crates/tv-core/src/input.rs`: `e00cf7ad4e2d14aaf87c904b9c8e1c053439600e8ebda3a0f21893abf0afd4a0`
- `crates/tv-cli/src/lib.rs`: `910568f9142abf81b0d89a32ce44aa2428b211da653fede926df65753be25dd8`
- Product `Cargo.lock`: `2383d99477ec8ad3b9132f4d41ae9f108ab7a8fb3b1e8299fa8c6b93ec810d35`

The final tested source snapshot archive SHA-256 was `017356c2b62dfd8345831c2e382b5680740327ad82ae48aad227af2ef076d5a6`; later additions are this validation record and maintainer documentation. Full commands, per-mutant diffs/logs/outcomes, source manifests and timing records are retained in the audit evidence archive.

## Security impact

Every successful result is still untrusted input. Parsing does not verify signatures, validate artifact kinds, enforce origin policy, or certify the platform. The byte cap is not a deadline for a blocking or indefinitely interrupted reader. The size cap and depth bound constrain resource use but do not promise a fixed small heap footprint. No production deployment or verifier release is justified by this parser-only evidence.
