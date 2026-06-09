# 🛡️ SaQura PQC Scan

**Find quantum-vulnerable cryptography in your code — for free.**

A GitHub Action (and CLI) that scans your **source code and dependency manifests** for
cryptography that will break once a cryptographically-relevant quantum computer arrives
— **RSA, ECC/ECDSA/ECDH, Diffie-Hellman** — plus already-broken primitives
(MD5, SHA-1, DES, RC4). It produces a **CycloneDX CBOM** (`cbom.json`) and a
**quantum-readiness report** right in your pull request.

> Regulators (EU **NIS2**, **BSI**) and NIST are pushing migration off RSA/ECC to
> post-quantum cryptography. The first step of every migration is **knowing where your
> crypto is.** This tool gives you that in 30 seconds — for free.

---

## Quick start (GitHub Action)

```yaml
# .github/workflows/pqc-scan.yml
name: PQC Scan
on: [pull_request]

permissions:
  contents: read
  pull-requests: write   # only needed for comment-on-pr

jobs:
  pqc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: kyototech/saqura-pqc-scan@v1
        with:
          path: '.'
          comment-on-pr: 'true'
          fail-on: 'none'      # or: vulnerable | broken | any
```

The report appears in the **job summary** and (optionally) as a **PR comment**;
the CycloneDX **CBOM** is written to `cbom.json` (upload it as an artifact if you like).

## Quick start (CLI)

```bash
npx saqura-pqc-scan .            # scan current directory, print report
npx saqura-pqc-scan ./src --cbom cbom.json --report report.md
npx saqura-pqc-scan . --fail-on vulnerable   # exit 1 if RSA/ECC/DH found
```

## What it detects

| Category | Examples |
|---|---|
| 🔴 **Quantum-vulnerable** | RSA, ECDSA, ECDH, DSA, Diffie-Hellman, ElGamal, named curves (P-256, Curve25519, Ed25519) |
| 🟠 **Broken / weak** | MD5, SHA-1, DES, 3DES, RC4, ECB mode |
| 🟡 **Mixed libraries** | BouncyCastle, pycryptodome, `cryptography` (verify usage) |
| 🟢 **Quantum-safe** | ML-KEM, ML-DSA, SLH-DSA, FrodoKEM, Classic McEliece, AES-256, SHA-256/3, ChaCha20 |

Scanned ecosystems: **.NET, Java/Kotlin, Swift, JS/TS, Python, Go** (source patterns) and
their dependency manifests (`*.csproj`, `build.gradle`, `pom.xml`, `package.json`,
`Package.swift`, `requirements.txt`, `pyproject.toml`, …).

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory to scan |
| `cbom-path` | `cbom.json` | Where to write the CycloneDX CBOM (empty to skip) |
| `report-path` | _(none)_ | Where to write the Markdown report |
| `badge-path` | _(none)_ | Where to write a shields.io badge JSON |
| `fail-on` | `none` | Fail the job at `vulnerable` \| `broken` \| `any` |
| `comment-on-pr` | `false` | Post/update a PR comment (needs `pull-requests: write`) |

## Outputs

`score` (0–100), `vulnerable-count`, `broken-count`, `cbom-path`.

## Scope & honesty

This scan is **heuristic** (pattern + dependency-manifest based). It scans **source code
and dependency manifests** in your repository. It does **not** detect runtime/compiled-binary
crypto, firmware, TLS/certificate configuration, or closed-source dependencies. False
positives and negatives are possible. **It is a starting point, not a compliance
certification.** The CBOM output is [CycloneDX](https://cyclonedx.org)-conformant.

## → Found quantum-vulnerable crypto? Fix it with SaQura

- **Migrate it yourself** — drop-in **hybrid post-quantum** crypto for .NET, Kotlin, Swift
  and JS. Free tier to try it: **[saqura.de/docs](https://saqura.de/docs)**
- **Want full coverage?** A **SaQura Readiness Assessment** also covers what this free scan
  can't — TLS/certificates, runtime, and a BSI/NIS2-mapped migration plan:
  **[saqura.de/contact](https://saqura.de/contact)**
- **See classic vs. quantum-safe in 30 seconds:** **[saqura.de/try](https://saqura.de/try)**

## License

MIT © KyotoTech LLC — see [LICENSE](LICENSE). This scanner is open source; the SaQura
cryptography SDK/API it links to is a commercial product.
