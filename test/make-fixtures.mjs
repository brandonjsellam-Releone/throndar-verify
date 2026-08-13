// Generates bridge-attested proof bundles used by test/cosignature.test.mjs.
//
// The crypto is taken from the shipped bundle itself (dist/throndar-verify.mjs)
// rather than from a separately installed copy of @noble/post-quantum, so the
// fixtures can never drift from what the CLI actually runs.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const distPath = path.join(here, '..', 'dist', 'throndar-verify.mjs');
const outDir = path.join(here, 'fixtures');

// Re-expose the bundle's internals: strip the CLI entrypoint, append exports.
const src = readFileSync(distPath, 'utf8');
const lib = src.replace(/main\(process\.argv\);\s*$/, '') +
  '\nexport { ml_dsa87, falcon1024, bridgeSignedBytes };\n';
const libPath = path.join(outDir, '_lib.mjs');
mkdirSync(outDir, { recursive: true });
writeFileSync(libPath, lib);

const { ml_dsa87, falcon1024, bridgeSignedBytes } = await import(
  'file://' + libPath.replace(/\\/g, '/')
);

const ANSWER = 'Throndar co-signature gating regression fixture.';
const b64 = (u8) => Buffer.from(u8).toString('base64');

const mld = ml_dsa87.keygen();
const fal = falcon1024.keygen();
const msg = bridgeSignedBytes(ANSWER);

const sigPrimary = ml_dsa87.sign(msg, mld.secretKey);
const sigSecondaryGood = falcon1024.sign(msg, fal.secretKey);

if (!ml_dsa87.verify(sigPrimary, msg, mld.publicKey)) throw new Error('primary self-check failed');
if (!falcon1024.verify(sigSecondaryGood, msg, fal.publicKey)) throw new Error('secondary self-check failed');

// The regression case: valid primary, corrupted Falcon co-signature.
const sigSecondaryBad = Uint8Array.from(sigSecondaryGood);
sigSecondaryBad[10] ^= 0xff;
sigSecondaryBad[40] ^= 0xff;
if (falcon1024.verify(sigSecondaryBad, msg, fal.publicKey)) throw new Error('corrupt sig unexpectedly verified');

const bridgeKeys = [
  { role: 'primary', alg: 'ML-DSA-87', public_key_b64: b64(mld.publicKey) },
  { role: 'secondary', alg: 'Falcon-1024', public_key_b64: b64(fal.publicKey) },
];

const bundle = (sigSecondary) => ({
  v: 1,
  kind: 'throndar-proof',
  created: 1786500000,
  answer: ANSWER,
  bridgeKeys,
  attestation: {
    key_id_primary: 'testprimarykeyid',
    sig_primary: b64(sigPrimary),
    ...(sigSecondary ? { sig_secondary: b64(sigSecondary) } : {}),
  },
});

const write = (name, obj) =>
  writeFileSync(path.join(outDir, name), JSON.stringify(obj, null, 2) + '\n');

write('dual-signed.json', bundle(sigSecondaryGood));
write('bad-cosignature.json', bundle(sigSecondaryBad));
write('primary-only.json', bundle(null));

// Co-signature claimed, but no secondary key supplied to check it against.
const noKey = bundle(sigSecondaryGood);
noKey.bridgeKeys = [bridgeKeys[0]];
write('cosignature-unverifiable.json', noKey);

console.log('fixtures written to test/fixtures/');
