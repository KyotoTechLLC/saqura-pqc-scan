// SaQura PQC Scan — scoring + Markdown report.

const SAQURA = {
  site: 'https://saqura.de',
  docs: 'https://saqura.de/docs',
  pricing: 'https://saqura.de/pricing',
  contact: 'https://saqura.de/contact',
  try: 'https://saqura.de/try',
};

/**
 * Aggregate findings into a summary.
 * @param {import('./scanner.js').Finding[]} findings
 */
export function summarize(findings) {
  const occ = { 'quantum-vulnerable': 0, broken: 0, 'quantum-safe': 0, unknown: 0 };
  const algos = {
    'quantum-vulnerable': new Map(),
    broken: new Map(),
    'quantum-safe': new Set(),
    unknown: new Map(),
  };
  for (const f of findings) {
    occ[f.category] = (occ[f.category] || 0) + 1;
    if (f.category === 'quantum-safe') {
      algos['quantum-safe'].add(f.name);
    } else {
      const m = algos[f.category];
      let e = m.get(f.name);
      if (!e) {
        e = { name: f.name, note: f.note, count: 0, locations: [] };
        m.set(f.name, e);
      }
      e.count++;
      if (e.locations.length < 5 && f.line != null) e.locations.push(`${f.file}:${f.line}`);
    }
  }

  const risky = occ['quantum-vulnerable'] + occ.broken + occ.unknown;
  const totalCrypto = risky + occ['quantum-safe'];
  const score = totalCrypto === 0 ? null : Math.round((occ['quantum-safe'] / totalCrypto) * 100);

  return {
    occ,
    score,
    totalCrypto,
    vulnerable: [...algos['quantum-vulnerable'].values()].sort((a, b) => b.count - a.count),
    broken: [...algos.broken.values()].sort((a, b) => b.count - a.count),
    unknown: [...algos.unknown.values()].sort((a, b) => b.count - a.count),
    safe: [...algos['quantum-safe']].sort(),
  };
}

function scoreLabel(score) {
  if (score == null) return 'no cryptography detected';
  if (score >= 90) return 'mostly quantum-safe';
  if (score >= 50) return 'partially quantum-safe';
  return 'at risk';
}

function scoreEmoji(score) {
  if (score == null) return '⚪';
  if (score >= 90) return '🟢';
  if (score >= 50) return '🟡';
  return '🔴';
}

/**
 * Render the Markdown report.
 * @param {ReturnType<typeof summarize>} s
 * @param {{ filesScanned: number, projectName: string }} meta
 */
export function renderMarkdown(s, meta) {
  const L = [];
  const emoji = scoreEmoji(s.score);
  const scoreText = s.score == null ? 'N/A' : `${s.score}%`;

  L.push('## 🛡️ SaQura PQC Scan — Quantum-Readiness Report');
  L.push('');
  L.push(`**Quantum-Readiness Score: ${emoji} ${scoreText}** (${scoreLabel(s.score)})`);
  L.push('');
  L.push(`Scanned **${meta.filesScanned}** files in \`${meta.projectName}\`.`);
  L.push('');

  // Summary table
  L.push('| Category | Findings |');
  L.push('|---|---:|');
  L.push(`| 🔴 Quantum-vulnerable (RSA/ECC/DH) | ${s.occ['quantum-vulnerable']} |`);
  L.push(`| 🟠 Broken / weak (MD5/SHA-1/DES/RC4) | ${s.occ.broken} |`);
  L.push(`| 🟡 Unknown (mixed libraries) | ${s.occ.unknown} |`);
  L.push(`| 🟢 Quantum-safe (ML-KEM/ML-DSA/AES-256…) | ${s.occ['quantum-safe']} |`);
  L.push('');

  const renderTable = (title, rows) => {
    if (!rows.length) return;
    L.push(`### ${title}`);
    L.push('');
    L.push('| Algorithm | Count | Example locations | Why it matters |');
    L.push('|---|---:|---|---|');
    for (const r of rows) {
      const locs = r.locations.length ? r.locations.map((l) => `\`${l}\``).join('<br>') : '—';
      L.push(`| **${r.name}** | ${r.count} | ${locs} | ${r.note} |`);
    }
    L.push('');
  };

  renderTable('🔴 Quantum-vulnerable crypto — migrate this', s.vulnerable);
  renderTable('🟠 Broken / weak crypto — replace this', s.broken);
  renderTable('🟡 Mixed libraries — verify usage', s.unknown);

  if (s.safe.length) {
    L.push('### 🟢 Quantum-safe / strong primitives detected');
    L.push('');
    L.push(s.safe.map((n) => `\`${n}\``).join(' · '));
    L.push('');
  }

  if (s.totalCrypto === 0) {
    L.push('> No cryptographic primitives were detected in the scanned scope. ' +
      'This does **not** mean the project is crypto-free — see scope below.');
    L.push('');
  }

  // Funnel CTA
  L.push('---');
  L.push('');
  if (s.occ['quantum-vulnerable'] > 0 || s.occ.broken > 0 || s.occ.unknown > 0) {
    L.push('### → Make it quantum-safe with SaQura');
    L.push('');
    L.push(`- **Migrate it yourself:** drop-in hybrid post-quantum crypto for .NET, Kotlin, Swift & JS — [SaQura SDK & API docs](${SAQURA.docs}). Free tier to try it.`);
    L.push(`- **Want a full picture?** A [SaQura Readiness Assessment](${SAQURA.contact}) also covers what this free scan can't — TLS/certificates, runtime, and a BSI/NIS2-mapped migration plan.`);
    L.push(`- **See it in 30 seconds:** [try classic vs. quantum-safe side by side](${SAQURA.try}).`);
  } else {
    L.push('### → Stay quantum-safe with SaQura');
    L.push('');
    L.push(`No quantum-vulnerable crypto surfaced in this scan. To keep it that way — and to cover what this scan can't (TLS/certificates, runtime) — see [SaQura](${SAQURA.site}).`);
  }
  L.push('');

  // Honest scope disclaimer
  L.push('<details><summary>Scope & honesty</summary>');
  L.push('');
  L.push('This scan is **heuristic** (pattern + dependency-manifest based). It scans **source code and dependency manifests** in this repository. It does **not** detect: runtime/compiled-binary crypto, firmware, TLS/certificate configuration, or closed-source dependencies. False positives and negatives are possible. It is a starting point for a conversation, not a compliance certification.');
  L.push('');
  L.push('CBOM output is [CycloneDX](https://cyclonedx.org)-conformant (`cbom.json`).');
  L.push('</details>');
  L.push('');

  return L.join('\n');
}

/** A short shields.io endpoint-style badge object. */
export function badge(score) {
  const color = score == null ? 'lightgrey' : score >= 90 ? 'brightgreen' : score >= 50 ? 'yellow' : 'red';
  return {
    schemaVersion: 1,
    label: 'quantum-readiness',
    message: score == null ? 'n/a' : `${score}%`,
    color,
  };
}
