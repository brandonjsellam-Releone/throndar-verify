# cargo-audit CI admission — 2026-10-11

Development infrastructure only. This directory is not a Cargo workspace or a
product dependency. Its Cargo.lock belongs to the unchanged upstream
cargo-audit 0.22.2 source archive, not to an invented wrapper package.

Upstream: <https://github.com/rustsec/rustsec>, Apache-2.0 OR MIT.
Pinned archive: <https://static.crates.io/crates/cargo-audit/cargo-audit-0.22.2.crate>.
`source.sha256` pins that archive and the admitted replacement lock. Cargo then
checks the registry checksums in that lock when fetching dependencies.

The upstream shipped lock was rejected: RUSTSEC-2026-0204 (crossbeam-epoch),
RUSTSEC-2026-0258 (h2), RUSTSEC-2026-0185 (quinn-proto),
RUSTSEC-2026-0285 (rustls), and three unsoundness warnings. An unchanged source
copy received a refreshed lock using Cargo 1.97.1. The resulting 381-dependency
lock passed cargo-audit 0.22.2 with `--deny warnings`, no advisory ignores,
against 1,296 advisories after a network refresh on 2026-10-11.

CI downloads and hashes the source archive, extracts it into `runner.temp`
outside any product Cargo workspace ancestor, replaces only Cargo.lock
with this reviewed lock, and uses `cargo +1.97.1 install --path ... --locked`.
It then audits both tool locks and the product lock against current advisories.
There is no unchecked `cargo install --version` fallback or `cargo update` in CI.
The audit executable must be bootstrapped before it can check itself; its prior
admission is the trust input. New advisories block the subsequent checks.

The tool was built successfully with default upstream features in the isolated
Linux audit VM using `--locked --offline`, and the installed binary ran the
product and tool checks successfully. Registry-source and freshly downloaded
archive-source copies compared byte-for-byte equal, excluding Cargo's cache
metadata and generated install/target directories. No upstream source was edited.

Installed audit binary SHA-256 for this VM build:
`f83c71215c5d9520700e236abd950a1dcfa3513275bc04930437f82192493d9d`.
This is an evidence hash, not a cross-machine reproducible-build claim.

The development tool graph includes vendor C/assembly cryptography (aws-lc).
That is operated tooling, not admitted product cryptography. It does not relax
the product's nine dependency bans or authorize use with product secrets.
No production keys, OAuth tokens or signing credentials are provided to this job.

GitHub-hosted execution and branch-protection configuration require separate
verification after publication; local admission does not claim remote CI passed.
