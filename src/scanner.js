// SaQura PQC Scan — filesystem walk + rule application.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, basename, extname, relative, sep } from 'node:path';
import { SOURCE_RULES, DEPENDENCY_RULES } from './rules.js';

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', 'bin', 'obj',
  '.gradle', '.idea', '.vscode', 'vendor', 'target', 'Pods', '.build',
  'DerivedData', 'packages', '__pycache__', '.venv', 'venv', 'coverage',
  '.next', '.nuxt', '.cache', 'tmp', 'temp',
]);

const SOURCE_EXTS = new Set([
  '.cs', '.vb', '.fs', '.java', '.kt', '.kts', '.swift', '.js', '.ts', '.jsx',
  '.tsx', '.mjs', '.cjs', '.py', '.go', '.rb', '.php', '.c', '.cc', '.cpp',
  '.h', '.hpp', '.rs', '.scala', '.m', '.mm', '.dart', '.ex', '.exs',
]);

const MANIFEST_NAMES = new Set([
  'packages.config', 'build.gradle', 'build.gradle.kts', 'pom.xml',
  'package.json', 'Package.swift', 'Package.resolved', 'requirements.txt',
  'pyproject.toml', 'go.mod', 'Cargo.toml', 'Gemfile', 'composer.json',
]);

const MAX_FILE_BYTES = 1_500_000;
const MAX_OCCURRENCES_PER_RULE_FILE = 50;

// PQC KEM/signature rule ids — their presence on a line marks a hybrid context.
const PQC_SAFE_RULE_IDS = new Set(['ml-kem', 'ml-dsa', 'slh-dsa', 'frodokem', 'mceliece']);

/**
 * @typedef {Object} Finding
 * @property {string} ruleId
 * @property {string} name
 * @property {import('./rules.js').Category} category
 * @property {number} nistLevel
 * @property {string} file       repo-relative path
 * @property {number} [line]
 * @property {string} evidence
 * @property {'source'|'dependency'} kind
 * @property {string} note
 */

function isManifest(name) {
  if (MANIFEST_NAMES.has(name)) return true;
  return name.endsWith('.csproj');
}

function manifestApplies(rule, name) {
  return rule.manifests.some((m) => {
    if (m === '*') return true;
    if (m === '*.csproj') return name.endsWith('.csproj');
    return m === name;
  });
}

/** Recursively collect candidate files under root. */
function walk(root, out = []) {
  let entries;
  try {
    entries = readdirSync(root, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const full = join(root, e.name);
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) {
      // skip known noise dirs and hidden dirs (.git, .gradle, ...)
      if (SKIP_DIRS.has(e.name) || e.name.startsWith('.')) continue;
      walk(full, out);
    } else if (e.isFile()) {
      out.push(full);
    }
  }
  return out;
}

/** Scan one source file line-by-line against SOURCE_RULES. */
function scanSource(absPath, relPath, findings) {
  let text;
  try {
    text = readFileSync(absPath, 'utf8');
  } catch {
    return;
  }
  if (/[\x00-\x08]/.test(text.slice(0, 4000))) return; // looks binary
  const lines = text.split(/\r?\n/);
  const perRuleCount = new Map();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 2000) continue;

    // First pass: which rules match this line.
    const matched = [];
    for (const rule of SOURCE_RULES) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(line)) matched.push(rule);
    }
    if (matched.length === 0) continue;

    // Hybrid suppression: an EC curve next to a PQC KEM/signature on the same
    // line is a hybrid construction (e.g. "X25519 + ML-KEM") — the right thing,
    // not a vulnerability. Drop the curve finding in that case.
    const hasPqcSafe = matched.some((r) => PQC_SAFE_RULE_IDS.has(r.id));
    const effective = hasPqcSafe ? matched.filter((r) => r.id !== 'ec-curves') : matched;

    for (const rule of effective) {
      const count = perRuleCount.get(rule.id) || 0;
      if (count >= MAX_OCCURRENCES_PER_RULE_FILE) continue;
      perRuleCount.set(rule.id, count + 1);
      findings.push({
        ruleId: rule.id,
        name: rule.name,
        category: rule.category,
        nistLevel: rule.nistLevel,
        file: relPath,
        line: i + 1,
        evidence: line.trim().slice(0, 200),
        kind: 'source',
        note: rule.note,
      });
    }
  }
}

/** Scan one manifest file against DEPENDENCY_RULES (line-based for location). */
function scanManifest(absPath, relPath, findings) {
  let text;
  try {
    text = readFileSync(absPath, 'utf8');
  } catch {
    return;
  }
  const name = basename(absPath);
  const lines = text.split(/\r?\n/);
  const seen = new Set();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const rule of DEPENDENCY_RULES) {
      if (!manifestApplies(rule, name)) continue;
      if (seen.has(rule.id)) continue;
      if (rule.match.test(line)) {
        seen.add(rule.id);
        findings.push({
          ruleId: rule.id,
          name: rule.name,
          category: rule.category,
          nistLevel: rule.nistLevel,
          file: relPath,
          line: i + 1,
          evidence: line.trim().slice(0, 200),
          kind: 'dependency',
          note: rule.note,
        });
      }
    }
  }
}

/**
 * Scan a directory tree.
 * @param {string} root
 * @returns {{findings: Finding[], filesScanned: number, root: string}}
 */
export function scan(root) {
  const files = walk(root);
  /** @type {Finding[]} */
  const findings = [];
  let filesScanned = 0;
  for (const abs of files) {
    let size = 0;
    try {
      size = statSync(abs).size;
    } catch {
      continue;
    }
    if (size > MAX_FILE_BYTES) continue;
    const name = basename(abs);
    const ext = extname(abs).toLowerCase();
    const rel = relative(root, abs).split(sep).join('/') || name;
    if (isManifest(name)) {
      scanManifest(abs, rel, findings);
      filesScanned++;
    } else if (SOURCE_EXTS.has(ext)) {
      scanSource(abs, rel, findings);
      filesScanned++;
    }
  }
  return { findings, filesScanned, root };
}
