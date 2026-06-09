#!/usr/bin/env node
// SaQura PQC Scan — GitHub Action entry. Zero runtime dependencies.
//
// Inputs arrive as INPUT_<NAME> env vars (GitHub convention). Results go to
// the job summary (GITHUB_STEP_SUMMARY), action outputs (GITHUB_OUTPUT), an
// optional PR comment (via the REST API), and a fail-on exit code.

import { writeFileSync, appendFileSync, readFileSync } from 'node:fs';
import { resolve, basename } from 'node:path';
import { scan } from './scanner.js';
import { buildCbom } from './cbom.js';
import { summarize, renderMarkdown, badge } from './report.js';

const VERSION = '0.1.0';
const MARKER = '<!-- saqura-pqc-scan -->';

function input(name, def = '') {
  const v = process.env[`INPUT_${name.toUpperCase().replace(/-/g, '_')}`];
  return v == null || v === '' ? def : v;
}

function setOutput(name, value) {
  const f = process.env.GITHUB_OUTPUT;
  if (f) appendFileSync(f, `${name}=${value}\n`);
}

function thresholdExceeded(level, occ) {
  switch (level) {
    case 'vulnerable': return occ['quantum-vulnerable'] > 0;
    case 'broken': return occ['quantum-vulnerable'] > 0 || occ.broken > 0;
    case 'any': return occ['quantum-vulnerable'] + occ.broken + occ.unknown > 0;
    default: return false;
  }
}

async function upsertPrComment(markdown, token) {
  try {
    const repo = process.env.GITHUB_REPOSITORY;
    const eventPath = process.env.GITHUB_EVENT_PATH;
    if (!repo || !token || !eventPath) return;
    const event = JSON.parse(readFileSync(eventPath, 'utf8'));
    const prNumber = event.pull_request?.number || event.issue?.number;
    if (!prNumber) return;

    const api = process.env.GITHUB_API_URL || 'https://api.github.com';
    const headers = {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'saqura-pqc-scan',
    };
    const body = `${MARKER}\n${markdown}`;

    // Find an existing SaQura comment to update (avoid spamming on re-runs).
    const listRes = await fetch(`${api}/repos/${repo}/issues/${prNumber}/comments?per_page=100`, { headers });
    if (listRes.ok) {
      const comments = await listRes.json();
      const existing = comments.find((c) => typeof c.body === 'string' && c.body.includes(MARKER));
      if (existing) {
        await fetch(`${api}/repos/${repo}/issues/comments/${existing.id}`, {
          method: 'PATCH', headers, body: JSON.stringify({ body }),
        });
        return;
      }
    }
    await fetch(`${api}/repos/${repo}/issues/${prNumber}/comments`, {
      method: 'POST', headers, body: JSON.stringify({ body }),
    });
  } catch (e) {
    console.error(`::warning::Could not post PR comment: ${e.message}`);
  }
}

async function main() {
  const scanPath = input('path', '.');
  const cbomPath = input('cbom-path', 'cbom.json');
  const reportPath = input('report-path', '');
  const badgePath = input('badge-path', '');
  const failOn = input('fail-on', 'none');
  const commentOnPr = input('comment-on-pr', 'false') === 'true';
  const token = input('token', process.env.GITHUB_TOKEN || '');

  const root = resolve(scanPath);
  const projectName = basename(root) || 'project';

  const { findings, filesScanned } = scan(root);
  const s = summarize(findings);
  const md = renderMarkdown(s, { filesScanned, projectName });

  // CBOM
  if (cbomPath) {
    writeFileSync(cbomPath, JSON.stringify(buildCbom(findings, { projectName, version: VERSION }), null, 2));
  }
  if (reportPath) writeFileSync(reportPath, md);
  if (badgePath) writeFileSync(badgePath, JSON.stringify(badge(s.score), null, 2));

  // Job summary
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, md + '\n');
  } else {
    console.log(md);
  }

  // Outputs
  setOutput('score', s.score == null ? '' : String(s.score));
  setOutput('vulnerable-count', String(s.occ['quantum-vulnerable']));
  setOutput('broken-count', String(s.occ.broken));
  setOutput('cbom-path', cbomPath);

  // Console notices
  console.log(`SaQura PQC Scan v${VERSION}: score=${s.score ?? 'N/A'} ` +
    `vulnerable=${s.occ['quantum-vulnerable']} broken=${s.occ.broken} (${filesScanned} files)`);
  if (s.occ['quantum-vulnerable'] > 0) {
    console.log(`::warning::${s.occ['quantum-vulnerable']} quantum-vulnerable cryptography finding(s) detected.`);
  }

  if (commentOnPr) await upsertPrComment(md, token);

  if (thresholdExceeded(failOn, s.occ)) {
    console.error(`::error::Quantum-readiness threshold '${failOn}' exceeded.`);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(`::error::saqura-pqc-scan failed: ${e.stack || e.message}`);
  process.exit(1);
});
