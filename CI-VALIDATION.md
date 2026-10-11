# Rust CI validation — 2026-10-11

Scope: Tier 1 Rust assurance gates and declarative build configuration for the
strict input boundary. No parser implementation, signature verification, trust
policy, production service, or legacy Node workflow was changed.

The new Rust workflow runs on every pull request, pushes to main, a weekly
schedule, and manual dispatch. It has read-only repository permissions and
checkout credential persistence disabled. There are no path filters, advisory
ignores, continue-on-error steps, or optional Rust test jobs. Repository branch
protection must separately require its test, quality and dependency checks.
That remote setting is separate from workflow execution; see the hosted follow-up.

## Hosted follow-up and workspace correction

Published commit `237aa095f3129a56d68bf9de5020bb193561c197` ran in GitHub
[Rust run 38131387823](https://github.com/brandonjsellam-Releone/throndar-verify/actions/runs/38131387823).
All four parser test jobs and formatting/lint passed. Dependency policy failed
closed before its checks: extracting cargo-audit below the product workspace
made Cargo reject the tool as an unlisted workspace member. The earlier local
build used a sibling source directory and did not exercise this ancestor lookup.
The separate legacy run `38131387774` passed both Node smoke jobs.

The correction extracts both unchanged tool archives into `runner.temp`, outside
the product workspace, and keeps the reviewed locks, hashes, install/target
locations and mandatory policy commands unchanged. No workspace membership or
vendor source was edited. The original failure was reproduced in the old Linux
layout. A fresh isolated snapshot `/home/audit/src/tv-ci-external-source-20261011`
completed both full corrected installations (audit 4m07s,
deny 4m01s). The new binaries passed both tool-lock audits, the product audit and
all four deny groups from the product root, with current advisory refresh.
Their binary and admitted-lock hashes matched the original admission receipts.

Raw fetch, setup, full build and policy receipts are
`rust-ci-external-source-*-20261011.log` in the evidence directory below. Local
builds used the equivalent external temporary directory and ran independently
in parallel; hosted CI retains sequential audit admission before the deny build.
The corrected workflow still requires a successful hosted run after publication.

Read-only GitHub checks on 2026-10-11 returned an empty ruleset list and explicit
`Branch not protected` for main. No repository policy was changed. A workflow
being mandatory in its own execution does not make it a required merge check.

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
after these tests. The hosted follow-up above supersedes the initial remote-run
status; it does not turn this original local record into hosted evidence.

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
