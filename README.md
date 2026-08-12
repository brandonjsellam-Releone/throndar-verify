# throndar-verify

Verify a **Throndar** proof **entirely offline** — a council answer, a shared transcript,
an Autopilot run evidence pack, a signed data export, a transparency-log signed tree head,
or a consistency (append-only) proof. No network, no `npm install`: `dist/throndar-verify.mjs`
is a single self-contained file with the post-quantum crypto and Throndar's pinned public
keys baked in.

> **Don't trust us — fail your pipeline if the proof doesn't verify.**

## What a pass means

- **Integrity + signature** — the post-quantum signatures embedded in the bundle
  (ML-DSA-87, plus a Falcon-1024 / FN-DSA co-signature where present — FN-DSA's FIPS 206 is
  still a draft) verify against the embedded keys, and the content hashes are unaltered.
  The co-signature is **optional but enforced**: a bundle that carries no
  `sig_secondary` still passes on the primary alone, but if a co-signature *is*
  present it must verify, or the bundle fails. A claimed co-signature with no
  secondary key to check it against also fails, rather than being skipped.
  The outcome is reported as `bridge.secondaryOk` / `bridge.secondaryUnverifiable`
  in `--json`.
- **Origin** (`--require-origin`) — the verifying keys are keys **Throndar publishes**,
  matched by key *material*, never a claimed label. A self-signed or non-Throndar bundle
  passes integrity but fails origin.

It does **not** attest the answer's *content* is correct — only that this exact artifact
was produced by the key holder and hasn't changed.

## CLI

```bash
node dist/throndar-verify.mjs --require-origin answer.throndar-proof.json   # one file
node dist/throndar-verify.mjs --require-origin ./proofs/                    # a directory (*.json)
node dist/throndar-verify.mjs --json ./proofs/                             # machine-readable report
curl -s https://throndar.ai/api/... | node dist/throndar-verify.mjs --require-origin   # stdin
```

**Exit codes:** `0` all verified · `1` a bundle failed / wasn't a bundle · `2` usage error.
Any non-zero fails a CI step. All six proof kinds are auto-detected per file.

## GitHub Action

```yaml
- uses: brandonjsellam-Releone/throndar-verify@v1
  with:
    bundle: artifacts/answer.throndar-proof.json   # a file, or a directory of *.json
    require-origin: "true"                          # reject anything not signed by a pinned Throndar key
```

## How it verifies

The same isomorphic verifier that runs in the browser at
[throndar.ai/verify/offline](https://throndar.ai/verify/offline) and behind the HTTP API at
`POST https://throndar.ai/api/v1/verify` — one implementation, three channels, so a CLI
verdict can never diverge from the site. Built from Throndar's verifiers; the pinned keys
are the ones published at [throndar.ai/status](https://throndar.ai/status).

## License

MIT — see [LICENSE](./LICENSE).
