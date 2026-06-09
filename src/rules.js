// SaQura PQC Scan — detection rules.
//
// Two kinds of rules:
//   - source patterns: regexes applied line-by-line to source files
//   - dependency rules: known crypto libraries matched in manifest files
//
// Categories:
//   quantum-vulnerable  RSA / ECC / DH family — broken by Shor's algorithm
//   broken              already weak/broken regardless of quantum (MD5, DES, ...)
//   quantum-safe        NIST PQC + strong symmetric/hash primitives
//   unknown             crypto present but class can't be determined (mixed libs)
//
// nistLevel: rough NIST quantum-security category (0 = not quantum-safe).

/** @typedef {'quantum-vulnerable'|'broken'|'quantum-safe'|'unknown'} Category */

/**
 * @typedef {Object} SourceRule
 * @property {string} id
 * @property {string} name         human/algorithm name shown in reports + CBOM
 * @property {Category} category
 * @property {number} nistLevel
 * @property {RegExp} pattern       MUST be created with the 'g' flag for line scanning
 * @property {string} note
 */

/**
 * @typedef {Object} DependencyRule
 * @property {string} id
 * @property {string} name
 * @property {Category} category
 * @property {number} nistLevel
 * @property {RegExp} match         matched against a dependency/package name
 * @property {string[]} manifests   manifest basenames this applies to ('*' = any)
 * @property {string} note
 */

// ---------------------------------------------------------------------------
// Source-code patterns
// ---------------------------------------------------------------------------

/** @type {SourceRule[]} */
export const SOURCE_RULES = [
  // --- Quantum-vulnerable: asymmetric crypto broken by Shor -----------------
  {
    id: 'rsa',
    name: 'RSA',
    category: 'quantum-vulnerable',
    nistLevel: 0,
    pattern: /\bRSA(?:CryptoServiceProvider|Cng|OAEP|PKCS1|SSA)?\b/g,
    note: 'RSA public-key crypto is broken by Shor’s algorithm on a CRQC.',
  },
  {
    id: 'ecdsa',
    name: 'ECDSA',
    category: 'quantum-vulnerable',
    nistLevel: 0,
    pattern: /\bECDSA\b/g,
    note: 'Elliptic-curve signatures (ECDSA) are quantum-vulnerable.',
  },
  {
    id: 'ecdh',
    name: 'ECDH',
    category: 'quantum-vulnerable',
    nistLevel: 0,
    pattern: /\bECDH(?:E)?\b|\bECDiffieHellman\b/g,
    note: 'Elliptic-curve key exchange (ECDH) is quantum-vulnerable.',
  },
  {
    id: 'ecdsa-dotnet',
    name: 'ECDsa (.NET)',
    category: 'quantum-vulnerable',
    nistLevel: 0,
    pattern: /\bECDsa\b/g,
    note: '.NET ECDsa uses quantum-vulnerable elliptic-curve crypto.',
  },
  {
    id: 'dsa',
    name: 'DSA',
    category: 'quantum-vulnerable',
    nistLevel: 0,
    // Lookbehind avoids matching the "DSA" inside ML-DSA / SLH-DSA / ECDSA.
    pattern: /(?<![\w-])DSA\b/g,
    note: 'DSA signatures rely on discrete-log, broken by Shor.',
  },
  {
    id: 'dh',
    name: 'Diffie-Hellman',
    category: 'quantum-vulnerable',
    nistLevel: 0,
    pattern: /\bDiffie[- ]?Hellman\b/g,
    note: 'Classic Diffie-Hellman key exchange is quantum-vulnerable.',
  },
  {
    id: 'elgamal',
    name: 'ElGamal',
    category: 'quantum-vulnerable',
    nistLevel: 0,
    pattern: /\bElGamal\b/g,
    note: 'ElGamal relies on discrete-log, broken by Shor.',
  },
  {
    id: 'ec-curves',
    name: 'Elliptic-curve (named curve)',
    category: 'quantum-vulnerable',
    nistLevel: 0,
    pattern: /\b(?:Curve25519|X25519|Ed25519|secp256[rk]1|secp384r1|secp521r1|prime256v1|P-?256|P-?384|P-?521|nistp(?:256|384|521))\b/g,
    note: 'Named elliptic curves (incl. Curve25519/Ed25519) are quantum-vulnerable.',
  },
  {
    id: 'jca-getinstance',
    name: 'JCA asymmetric (getInstance)',
    category: 'quantum-vulnerable',
    nistLevel: 0,
    pattern: /getInstance\(\s*"(?:RSA|EC|ECDSA|ECDH|DSA|DiffieHellman|DH)[^"]*"/g,
    note: 'Java/Kotlin JCA requests a quantum-vulnerable asymmetric algorithm.',
  },
  {
    id: 'node-generatekeypair',
    name: 'Node crypto asymmetric keygen',
    category: 'quantum-vulnerable',
    nistLevel: 0,
    pattern: /generateKeyPair(?:Sync)?\(\s*['"](?:rsa|ec|dsa|dh|x25519|ed25519|x448|ed448)['"]/g,
    note: 'Node.js crypto generates a quantum-vulnerable asymmetric key pair.',
  },
  {
    id: 'sec-keytype',
    name: 'Apple SecKey asymmetric',
    category: 'quantum-vulnerable',
    nistLevel: 0,
    pattern: /kSecAttrKeyType(?:RSA|EC|ECSECPrimeRandom)\b/g,
    note: 'Apple Security framework uses quantum-vulnerable RSA/EC keys.',
  },

  // --- Already broken / weak ------------------------------------------------
  {
    id: 'md5',
    name: 'MD5',
    category: 'broken',
    nistLevel: 0,
    pattern: /\bMD5\b/g,
    note: 'MD5 is cryptographically broken (collisions).',
  },
  {
    id: 'sha1',
    name: 'SHA-1',
    category: 'broken',
    nistLevel: 0,
    pattern: /\bSHA-?1\b/g,
    note: 'SHA-1 is broken (collisions) and deprecated.',
  },
  {
    id: 'des',
    name: 'DES',
    category: 'broken',
    nistLevel: 0,
    // Case-sensitive on purpose: avoid matching German word "des" in comments.
    pattern: /\bDES\b/g,
    note: 'Single DES has a 56-bit key and is broken.',
  },
  {
    id: '3des',
    name: 'Triple DES',
    category: 'broken',
    nistLevel: 0,
    pattern: /\b(?:3DES|TripleDES|DESede)\b/g,
    note: '3DES is deprecated (Sweet32, small block size).',
  },
  {
    id: 'rc4',
    name: 'RC4',
    category: 'broken',
    nistLevel: 0,
    pattern: /\b(?:RC4|ARC4|ARCFOUR)\b/g,
    note: 'RC4 stream cipher is broken.',
  },
  {
    id: 'ecb',
    name: 'ECB mode',
    category: 'broken',
    nistLevel: 0,
    pattern: /\bECB\b/g,
    note: 'ECB block-cipher mode leaks plaintext structure.',
  },

  // --- Quantum-safe (good news; also prevents misclassification) ------------
  {
    id: 'ml-kem',
    name: 'ML-KEM (Kyber)',
    category: 'quantum-safe',
    nistLevel: 3,
    pattern: /\b(?:ML-?KEM|MLKEM|Kyber(?:512|768|1024)?)\b/g,
    note: 'ML-KEM (FIPS 203) is a NIST post-quantum KEM.',
  },
  {
    id: 'ml-dsa',
    name: 'ML-DSA (Dilithium)',
    category: 'quantum-safe',
    nistLevel: 3,
    pattern: /\b(?:ML-?DSA|MLDSA|Dilithium)\b/g,
    note: 'ML-DSA (FIPS 204) is a NIST post-quantum signature.',
  },
  {
    id: 'slh-dsa',
    name: 'SLH-DSA (SPHINCS+)',
    category: 'quantum-safe',
    nistLevel: 3,
    pattern: /\b(?:SLH-?DSA|SPHINCS\+?)\b/g,
    note: 'SLH-DSA (FIPS 205) is a NIST post-quantum signature.',
  },
  {
    id: 'frodokem',
    name: 'FrodoKEM',
    category: 'quantum-safe',
    nistLevel: 3,
    pattern: /\bFrodoKEM\b/g,
    note: 'FrodoKEM is a conservative (BSI-profile) post-quantum KEM.',
  },
  {
    id: 'mceliece',
    name: 'Classic McEliece',
    category: 'quantum-safe',
    nistLevel: 5,
    pattern: /\b(?:Classic[- ]?)?McEliece\b/g,
    note: 'Classic McEliece is a conservative post-quantum KEM.',
  },
  {
    id: 'aes',
    name: 'AES',
    category: 'quantum-safe',
    nistLevel: 1,
    pattern: /\bAES-?(?:128|192|256)?\b/g,
    note: 'AES (≥128-bit) is considered quantum-resistant; AES-256 recommended.',
  },
  {
    id: 'sha2-3',
    name: 'SHA-2 / SHA-3',
    category: 'quantum-safe',
    nistLevel: 2,
    pattern: /\b(?:SHA-?(?:256|384|512)|SHA-?3|SHA3|SHAKE(?:128|256)?)\b/g,
    note: 'SHA-2/SHA-3 (≥256-bit) are considered quantum-resistant.',
  },
  {
    id: 'chacha20',
    name: 'ChaCha20',
    category: 'quantum-safe',
    nistLevel: 1,
    pattern: /\bChaCha20\b/g,
    note: 'ChaCha20 (256-bit) is considered quantum-resistant.',
  },
];

// ---------------------------------------------------------------------------
// Dependency rules
// ---------------------------------------------------------------------------

const JS_MANIFEST = ['package.json'];
const DOTNET_MANIFEST = ['*.csproj', 'packages.config'];
const JAVA_MANIFEST = ['build.gradle', 'build.gradle.kts', 'pom.xml'];
const SWIFT_MANIFEST = ['Package.swift', 'Package.resolved'];
const PY_MANIFEST = ['requirements.txt', 'pyproject.toml'];

/** @type {DependencyRule[]} */
export const DEPENDENCY_RULES = [
  // JS/TS
  { id: 'dep-node-forge', name: 'node-forge', category: 'quantum-vulnerable', nistLevel: 0, match: /(?:^|["/])node-forge\b/, manifests: JS_MANIFEST, note: 'node-forge ships RSA/ECC (quantum-vulnerable).' },
  { id: 'dep-jsrsasign', name: 'jsrsasign', category: 'quantum-vulnerable', nistLevel: 0, match: /\bjsrsasign\b/, manifests: JS_MANIFEST, note: 'jsrsasign implements RSA/ECDSA (quantum-vulnerable).' },
  { id: 'dep-elliptic', name: 'elliptic', category: 'quantum-vulnerable', nistLevel: 0, match: /(?:^|["/])elliptic\b/, manifests: JS_MANIFEST, note: 'elliptic implements ECC (quantum-vulnerable).' },
  { id: 'dep-tweetnacl', name: 'tweetnacl', category: 'quantum-vulnerable', nistLevel: 0, match: /\btweetnacl\b/, manifests: JS_MANIFEST, note: 'tweetnacl uses Curve25519/Ed25519 (quantum-vulnerable).' },
  // .NET
  { id: 'dep-bouncycastle-net', name: 'BouncyCastle (.NET)', category: 'unknown', nistLevel: 0, match: /BouncyCastle/i, manifests: DOTNET_MANIFEST, note: 'BouncyCastle is mixed; classic RSA/ECC unless PQC is explicitly used.' },
  // Java/Kotlin
  { id: 'dep-bouncycastle-java', name: 'BouncyCastle (Java)', category: 'unknown', nistLevel: 0, match: /org\.bouncycastle/i, manifests: JAVA_MANIFEST, note: 'BouncyCastle is mixed; classic RSA/ECC unless PQC is explicitly used.' },
  // Swift
  { id: 'dep-swift-crypto', name: 'swift-crypto', category: 'quantum-vulnerable', nistLevel: 0, match: /swift-crypto/i, manifests: SWIFT_MANIFEST, note: 'swift-crypto exposes P256/Curve25519 (quantum-vulnerable).' },
  // Python
  { id: 'dep-py-rsa', name: 'rsa (PyPI)', category: 'quantum-vulnerable', nistLevel: 0, match: /(?:^|["'\s=])rsa\b/, manifests: PY_MANIFEST, note: 'PyPI "rsa" implements RSA (quantum-vulnerable).' },
  { id: 'dep-py-ecdsa', name: 'ecdsa (PyPI)', category: 'quantum-vulnerable', nistLevel: 0, match: /\becdsa\b/, manifests: PY_MANIFEST, note: 'PyPI "ecdsa" implements ECDSA (quantum-vulnerable).' },
  { id: 'dep-py-pycryptodome', name: 'pycryptodome', category: 'unknown', nistLevel: 0, match: /\bpycryptodome\b/, manifests: PY_MANIFEST, note: 'pycryptodome is mixed; check for RSA/ECC usage.' },
  { id: 'dep-py-cryptography', name: 'cryptography', category: 'unknown', nistLevel: 0, match: /\bcryptography\b/, manifests: PY_MANIFEST, note: 'Python "cryptography" is mixed; check for RSA/ECC usage.' },

  // PQC-positive dependencies (good news)
  { id: 'dep-saqura', name: 'SaQura', category: 'quantum-safe', nistLevel: 3, match: /\bsaqura\b/i, manifests: ['*'], note: 'SaQura provides hybrid post-quantum crypto.' },
  { id: 'dep-liboqs', name: 'liboqs / open-quantum-safe', category: 'quantum-safe', nistLevel: 3, match: /(?:liboqs|open-quantum-safe|oqs)/i, manifests: ['*'], note: 'Open Quantum Safe provides PQC primitives.' },
  { id: 'dep-pqcrypto', name: 'pqcrypto', category: 'quantum-safe', nistLevel: 3, match: /\bpqcrypto\b/i, manifests: ['*'], note: 'pqcrypto provides post-quantum primitives.' },
];
