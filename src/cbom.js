// SaQura PQC Scan — CycloneDX 1.6 CBOM generator.
//
// One `cryptographic-asset` component per distinct algorithm, with the
// locations it was found and a rough NIST quantum-security level.

import { randomUUID } from 'node:crypto';

// Map a rule/algorithm name to a CycloneDX crypto "primitive".
const PRIMITIVE = {
  RSA: 'pke',
  ECDSA: 'signature',
  'ECDsa (.NET)': 'signature',
  ECDH: 'key-agree',
  DSA: 'signature',
  'Diffie-Hellman': 'key-agree',
  ElGamal: 'pke',
  'Elliptic-curve (named curve)': 'key-agree',
  'JCA asymmetric (getInstance)': 'pke',
  'Node crypto asymmetric keygen': 'pke',
  'Apple SecKey asymmetric': 'pke',
  MD5: 'hash',
  'SHA-1': 'hash',
  DES: 'block-cipher',
  'Triple DES': 'block-cipher',
  RC4: 'stream-cipher',
  'ECB mode': 'block-cipher',
  'ML-KEM (Kyber)': 'kem',
  'ML-DSA (Dilithium)': 'signature',
  'SLH-DSA (SPHINCS+)': 'signature',
  FrodoKEM: 'kem',
  'Classic McEliece': 'kem',
  AES: 'block-cipher',
  'SHA-2 / SHA-3': 'hash',
  ChaCha20: 'stream-cipher',
};

/**
 * @param {import('./scanner.js').Finding[]} findings
 * @param {{ projectName?: string, version?: string, timestamp?: string }} [opts]
 */
export function buildCbom(findings, opts = {}) {
  const projectName = opts.projectName || 'scanned-project';
  const toolVersion = opts.version || '1.0.0';
  const timestamp = opts.timestamp || new Date().toISOString();

  // Group by algorithm name.
  const byName = new Map();
  for (const f of findings) {
    let g = byName.get(f.name);
    if (!g) {
      g = { name: f.name, category: f.category, nistLevel: f.nistLevel, occ: [] };
      byName.set(f.name, g);
    }
    g.occ.push(f.line != null ? `${f.file}:${f.line}` : f.file);
  }

  const components = [...byName.values()].map((g) => {
    const ref = 'crypto/' + g.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    return {
      type: 'cryptographic-asset',
      'bom-ref': ref,
      name: g.name,
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: PRIMITIVE[g.name] || 'unknown',
          nistQuantumSecurityLevel: g.nistLevel,
        },
      },
      evidence: {
        occurrences: g.occ.slice(0, 100).map((loc) => ({ location: loc })),
      },
      properties: [
        { name: 'saqura:category', value: g.category },
        { name: 'saqura:occurrences', value: String(g.occ.length) },
      ],
    };
  });

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: 'urn:uuid:' + randomUUID(),
    version: 1,
    metadata: {
      timestamp,
      tools: {
        components: [
          {
            type: 'application',
            group: 'KyotoTech',
            name: 'saqura-pqc-scan',
            version: toolVersion,
          },
        ],
      },
      component: { type: 'application', name: projectName },
    },
    components,
  };
}
