// Minimal regression test — no test framework, just assertions.
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scan } from '../src/scanner.js';
import { summarize } from '../src/report.js';
import { buildCbom } from '../src/cbom.js';

const here = dirname(fileURLToPath(import.meta.url));
const examples = join(here, '..', 'examples');

let failures = 0;
function check(label, cond) {
  if (cond) {
    console.log(`  ✓ ${label}`);
  } else {
    console.error(`  ✗ ${label}`);
    failures++;
  }
}

const { findings, filesScanned } = scan(examples);
const s = summarize(findings);
const names = new Set(findings.map((f) => f.name));
const vulnNames = new Set(findings.filter((f) => f.category === 'quantum-vulnerable').map((f) => f.name));
const inSafeFile = findings.filter((f) => f.file.includes('safe-app') && f.category === 'quantum-vulnerable');

console.log('SaQura PQC Scan — tests');
check('scanned the example files', filesScanned >= 4);
check('detects RSA', names.has('RSA'));
check('detects ECDsa', names.has('ECDsa (.NET)'));
check('detects MD5 (broken)', names.has('MD5'));
check('detects RC4 (broken)', names.has('RC4'));
check('detects node-forge dependency', names.has('node-forge'));
check('detects ML-KEM as quantum-safe', s.safe.includes('ML-KEM (Kyber)'));
check('detects ML-DSA as quantum-safe', s.safe.includes('ML-DSA (Dilithium)'));
check('does NOT flag ML-DSA as DSA (no vuln in safe-app)', inSafeFile.length === 0);
check('ML-DSA is not in vulnerable set', !vulnNames.has('DSA') || inSafeFile.length === 0);
check('score is a number between 0 and 100', s.score >= 0 && s.score <= 100);
check('has quantum-vulnerable findings', s.occ['quantum-vulnerable'] > 0);

const cbom = buildCbom(findings, { projectName: 'examples' });
check('CBOM is CycloneDX 1.6', cbom.bomFormat === 'CycloneDX' && cbom.specVersion === '1.6');
check('CBOM has a urn:uuid serialNumber', /^urn:uuid:/.test(cbom.serialNumber));
check('CBOM components are cryptographic-asset', cbom.components.every((c) => c.type === 'cryptographic-asset'));
check('CBOM tags NIST quantum security level', cbom.components.every((c) => typeof c.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel === 'number'));

if (failures) {
  console.error(`\n${failures} test(s) failed`);
  process.exit(1);
}
console.log('\nAll tests passed');
