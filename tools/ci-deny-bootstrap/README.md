# cargo-deny CI admission — 2026-10-11

Development infrastructure only. This directory is not a Cargo workspace or a
product dependency. Its Cargo.lock belongs to unchanged cargo-deny 0.20.2 source.
Upstream: <https://github.com/EmbarkStudios/cargo-deny>, MIT OR Apache-2.0.
Pinned archive: <https://static.crates.io/crates/cargo-deny/cargo-deny-0.20.2.crate>.
`source.sha256` pins both the archive and admitted replacement lock.

The upstream shipped lock was rejected for rustls / RUSTSEC-2026-0285. An
unchanged source copy received a refreshed lock using Cargo 1.97.1. The resulting
199-dependency lock passed cargo-audit 0.22.2 with `--deny warnings` and no ignores
against 1,296 advisories on 2026-10-11. The same database was refreshed that day.

CI audits this lock before building the tool, hashes and extracts the archive,
copies this lock over the shipped one, and installs with exact Rust 1.97.1 and
`--locked`. Installation succeeded using `--offline` in the isolated Linux VM.
The installed binary passed the real product policies and rejected deliberately
introduced banned dependencies. No registry source was patched.

Registry-source and freshly downloaded archive-source copies compared equal,
excluding Cargo's cache metadata and generated install/target directories.
Installed deny binary SHA-256 for this VM build:
`3e776abbf6d9aefe8806508db7253ed098bdcbbac983ce46c084a56df7818560`.
This is an evidence hash, not a portable binary reproducibility guarantee.

The tool itself depends on ring. This development infrastructure exception does
not put ring in the product graph and does not weaken the product ban. The policy
job has read-only repository permissions and receives no production credentials.

Remote GitHub execution and required branch-protection checks remain to be
verified after publication. Missing tool provisioning fails the job; there is no
skip, permissive fallback, advisory ignore, or continue-on-error path.
