#!/usr/bin/env node
// SaQura PQC Scan — CLI entry.
//
// Usage:
//   node src/cli.js [path] [--cbom cbom.json] [--report report.md]
//                          [--json] [--fail-on none|vulnerable|broken|any]
//
// Exit codes: 0 = below threshold, 1 = threshold exceeded, 2 = usage error.

import { writeFileSync } from 'node:fs';
import { resolve, basename } from 'node:path';
import { scan } from './scanner.js';
import { buildCbom } from './cbom.js';
import { summarize, renderMarkdown, badge } from './report.js';

const VERSION = '0.1.0';

function parseArgs(argv) {
  const opts = { path: '.', cbom: null, report: null, json: false, failOn: 'none', badge: null };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--cbom') opts.cbom = argv[++i];
    else if (a === '--report') opts.report = argv[++i];
    else if (a === '--badge') opts.badge = argv[++i];
    else if (a === '--json') opts.json = true;
    else if (a === '--fail-on') opts.failOn = argv[++i];
    else if (a === '--version' || a === '-v') { console.log(VERSION); process.exit(0); }
    else if (a === '--help' || a === '-h') { printHelp(); process.exit(0); }
    else if (a.startsWith('-')) { console.error(`Unknown flag: ${a}`); process.exit(2); }
    else rest.push(a);
  }
  if (rest.length) opts.path = rest[0];
  return opts;
}

function printHelp() {
  console.log(`SaQura PQC Scan v${VERSION}
Find quantum-vulnerable cryptography in your code.

Usage:
  saqura-pqc-scan [path] [options]

Options:
  --cbom <file>       write CycloneDX CBOM JSON
  --report <file>     write Markdown report
  --badge <file>      write shields.io badge JSON
  --json              print summary JSON to stdout
  --fail-on <level>   exit 1 if findings at/above level:
                      none (default) | vulnerable | broken | any
  -v, --version       print version
  -h, --help          show this help

More: https://saqura.de`);
}

function thresholdExceeded(level, occ) {
  switch (level) {
    case 'vulnerable': return occ['quantum-vulnerable'] > 0;
    case 'broken': return occ['quantum-vulnerable'] > 0 || occ.broken > 0;
    case 'any': return occ['quantum-vulnerable'] + occ.broken + occ.unknown > 0;
    default: return false;
  }
}

export function run(argv) {
  const opts = parseArgs(argv);
  const root = resolve(opts.path);
  const projectName = basename(root) || 'project';

  const { findings, filesScanned } = scan(root);
  const s = summarize(findings);

  if (opts.cbom) {
    writeFileSync(opts.cbom, JSON.stringify(buildCbom(findings, { projectName, version: VERSION }), null, 2));
  }
  const md = renderMarkdown(s, { filesScanned, projectName });
  if (opts.report) writeFileSync(opts.report, md);
  if (opts.badge) writeFileSync(opts.badge, JSON.stringify(badge(s.score), null, 2));

  if (opts.json) {
    console.log(JSON.stringify({ score: s.score, occ: s.occ, filesScanned }, null, 2));
  } else {
    console.log(md);
  }

  return {
    summary: s,
    filesScanned,
    exitCode: thresholdExceeded(opts.failOn, s.occ) ? 1 : 0,
  };
}

// Run when invoked directly.
if (import.meta.url === `file://${process.argv[1]}`) {
  const { exitCode } = run(process.argv.slice(2));
  process.exit(exitCode);
}
