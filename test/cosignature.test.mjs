// Regression test: a PRESENT Falcon-1024 co-signature must gate the verdict.
//
// Before this test existed, `allOk` was computed from the ML-DSA-87 primary
// alone, so a bundle carrying a present-but-invalid co-signature verified
// clean — and `--json` did not expose the co-signature result, so a CI
// consumer had no way to notice.
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(here, '..', 'dist', 'throndar-verify.mjs');
const fixture = (n) => path.join(here, 'fixtures', n);

function run(args) {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
    return { code: 0, stdout };
  } catch (e) {
    return { code: e.status ?? 1, stdout: e.stdout ?? '' };
  }
}

const failures = [];
const check = (name, cond, detail) => {
  if (cond) {
    console.log(`  ok  ${name}`);
  } else {
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
    failures.push(name);
  }
};

console.log('co-signature gating:');

// 1. A valid dual-signed bundle still passes.
{
  const r = run([fixture('dual-signed.json')]);
  check('valid dual-signed bundle passes', r.code === 0, `exit ${r.code}`);
  check('valid dual-signed bundle is reported as dual-signed', /dual-signed/.test(r.stdout), r.stdout.trim());
}

// 2. THE REGRESSION: present-but-invalid co-signature must fail.
{
  const r = run([fixture('bad-cosignature.json')]);
  check('invalid co-signature FAILS verification', r.code === 1, `exit ${r.code}: ${r.stdout.trim()}`);
  check('invalid co-signature is named in the output', /co-signature FAILED/.test(r.stdout), r.stdout.trim());
}

// 3. Absent co-signature stays valid (co-signing remains optional).
{
  const r = run([fixture('primary-only.json')]);
  check('primary-only bundle still passes', r.code === 0, `exit ${r.code}`);
}

// 4. Claimed co-signature with no key to check it against fails closed.
{
  const r = run([fixture('cosignature-unverifiable.json')]);
  check('unverifiable co-signature fails closed', r.code === 1, `exit ${r.code}`);
}

// 5. The co-signature result is machine-readable via --json.
{
  const r = run(['--json', fixture('bad-cosignature.json')]);
  let report;
  try {
    report = JSON.parse(r.stdout);
  } catch {
    report = null;
  }
  const bridge = report?.results?.[0]?.bridge;
  check('--json exposes bridge', Boolean(bridge), JSON.stringify(report?.results?.[0] ?? null));
  check('--json reports secondaryOk=false', bridge?.secondaryOk === false, JSON.stringify(bridge));
  check('--json reports primaryOk=true', bridge?.primaryOk === true, JSON.stringify(bridge));
  check('--json marks the bundle as not passing', report?.results?.[0]?.pass === false);
}

if (failures.length) {
  console.error(`\n${failures.length} check(s) failed`);
  process.exit(1);
}
console.log('\nall co-signature checks passed');
