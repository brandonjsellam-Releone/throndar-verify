# Mutation runner admission

This standalone development workspace fetches the pinned cargo-mutants package
and dependency sources into the isolated Linux audit VM. It is not part of the
verifier workspace or its production graph. Do not build or publish this crate.

Upstream package: cargo-mutants 27.1.0, MIT license.
Source: https://github.com/sourcefrog/cargo-mutants
Installation guidance: https://mutants.rs/installation.html

After fetching, audit the tool's dependency lock before installation. The shipped
27.1.0 lock was rejected during admission because it contained a vulnerable
crossbeam-epoch release. A separately copied, unchanged tool source tree received
a freshly resolved lock, which was audited and used for offline `--locked`
installation. Preserve the admitted lock and binary hashes with the run evidence;
do not substitute an unaudited install or patch the registry source.

All mutation runs require a
passing baseline. A build error, timeout, or tool failure is not a caught mutant;
inspect the named test assertion in the result log.
