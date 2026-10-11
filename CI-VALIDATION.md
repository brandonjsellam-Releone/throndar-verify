# Rust CI validation — 2026-10-11

Scope: Tier 1 Rust assurance gates and declarative build configuration for the
strict input boundary. No parser implementation, signature verification, trust
policy, production service, or legacy Node workflow was changed.

The new Rust workflow runs on every pull request, pushes to main, a weekly
schedule, and manual dispatch. It has read-only repository permissions and
checkout credential persistence disabled. There are no path filters, advisory
ignores, continue-on-error steps, or optional Rust test jobs. Repository branch
protection must separately require its test, quality and dependency checks.
That remote setting was not modified or verified in this change.

## Executed locally in isolated Linux

Source worktree: `throndar-verify-rust-publish`, parent HEAD
`22c9f269e2d119c7916e969d2e05ba17752cd64e`.
Snapshot: `/home/audit/src/tv-rust-ci-20261011`.

| Check | Result |
| --- | --- |
| Rust 1.90.0 MSRV, dev and release, workspace all-feature/all-target tests | 37 passed in each profile |
| Rust 1.97.1, dev and release, same full suite | 37 passed in each profile |
| Separate doc-test entrypoint, both compilers and profiles | Passed; currently zero doc tests |
| Rust 1.97.1 format check | Passed |
| Rust 1.97.1 all-target/all-feature clippy, `-D warnings` | Passed |
| Newly bootstrapped cargo-audit, product lock, `--deny warnings` | Passed; 15 lockfile packages |
| Newly bootstrapped cargo-deny, all four policy groups | Passed |
| Inject normal dependency `ring = 0.17.14` | Failed specifically `error[banned]` |
| Remove only ring policy entry while that dependency remains | Passed; proves the ban is load-bearing |
| Restore manifest, lock and policy | Original SHA-256 values restored; gate passed |

Tests ran through the existing credential-free Linux wrapper, with network
disabled except source downloads and advisory refresh. They did not run on the
Windows checkout. The legacy Node suite was not rerun for this configuration-only
change; its existing workflow remains unchanged and must remain required.

The original source snapshot predates a correction placing cargo-deny's global
`--config` option before `check`, and the admission Markdown receipts. The final
command form was subsequently executed successfully. No product source changed
after these tests. No claim is made that GitHub has executed the new workflow.

## Reproduction

The workflow itself is the exact command manifest. From the repository root:

    cargo +1.90.0 test --workspace --locked --all-features --all-targets --no-fail-fast --profile dev
    cargo +1.90.0 test --workspace --locked --all-features --all-targets --no-fail-fast --profile release
    cargo +1.97.1 test --workspace --locked --all-features --all-targets --no-fail-fast --profile dev
    cargo +1.97.1 test --workspace --locked --all-features --all-targets --no-fail-fast --profile release
    cargo +1.97.1 fmt --all -- --check
    cargo +1.97.1 clippy --workspace --locked --all-targets --all-features -- -D warnings
    .ci-tools/install/bin/cargo-audit audit --deny warnings --file Cargo.lock
    .ci-tools/install/bin/cargo-deny --locked --config deny.toml check

The source and patched dependency locks for the two development tools are pinned
and explained under `tools/ci-audit-bootstrap` and `tools/ci-deny-bootstrap`.
Neither directory is part of this workspace's product graph. The vulnerable
upstream shipped locks are not installed by CI. The audit tool's reviewed build
is the bootstrap trust input; its self-audit cannot remove that bootstrap trust.

## Evidence and remaining release requirements

Local receipts are in
`C:\dev\_codex\reports\astra-blueprint-2026-10-08\`:
`rust-ci-policy-controls-20261011.log`, `rust-ci-supply-chain-20261011.log`,
`rust-ci-source-admission-20261011.log`, and `rust-ci-implementation-20261011.md`.
Detailed first build and test output also remains in the Codex tool transcript.
Do not describe these as a GitHub Actions run.

Before merging, independently review this diff, publish it, confirm all Rust and
legacy check results on the exact resulting commit, and verify required checks
in branch protection. No commit, push, merge, or deployment was performed by the
CI implementation worker. Existing parser mutation receipts and the missing
cryptographic verifier/trust-policy work remain separately scoped.
