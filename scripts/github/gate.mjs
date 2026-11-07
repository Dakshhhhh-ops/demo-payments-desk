#!/usr/bin/env node
// The desk's git gate as a GitHub check. GitHub Actions runs it from the
// `desk` branch of a GitHub copy of the desk's origin (see replay.mjs), in a
// bare clone of that repository, with the desk's public keys in desk-keys/.
//
// It runs the same rules as the origin's pre-receive hook (../pre-receive.mjs):
//   - every open pull request into main: its head commit needs the reviewer's
//     signed approval, the annotated tag refs/tags/approved/<sha>;
//   - every commit on main after the planted code: a signed "Ship F<n>" merge
//     of an approved commit with nothing added, or a signed "Accept risk F<n>".
// Each result is posted as a commit status (desk-gate/approval on a PR's head,
// desk-gate/main on each commit of main), so it shows on the pull request and
// in the commit list.
//
// github.com has no pre-receive hooks (only GitHub Enterprise Server does), so
// GitHub reports a bad push here instead of refusing it; the desk's own origin
// still refuses it outright. Nothing from a pull request is ever run: the PR's
// commits are only read as git objects.
//
//   node gate.mjs            check every open PR and all of main, post statuses
//   node gate.mjs --dry-run  the same, print only
import { execFileSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { checkApproval, checkMain } from '../pre-receive.mjs';

const ZERO = '0'.repeat(40);
const dry = process.argv.includes('--dry-run');
const repo = process.env.GITHUB_REPOSITORY;
const git = (...a) => execFileSync('git', a, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const tryGit = (...a) => {
  try {
    return git(...a);
  } catch {
    return null;
  }
};
const gh = (...a) => execFileSync('gh', a, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();

const results = [];
function post(sha, context, problems, okText) {
  const state = problems.length ? 'failure' : 'success';
  const description = (problems[0] ?? okText).slice(0, 140);
  results.push({ sha, context, state, description, problems });
  if (dry || !repo) return;
  gh('api', '-X', 'POST', `repos/${repo}/statuses/${sha}`, '-f', `state=${state}`, '-f', `context=${context}`, '-f', `description=${description}`,
    '-f', `target_url=${process.env.GITHUB_SERVER_URL}/${repo}/actions/runs/${process.env.GITHUB_RUN_ID}`);
}

// Pull requests: the head commit must carry the reviewer's signed approval.
const prs = repo ? JSON.parse(gh('pr', 'list', '--repo', repo, '--state', 'open', '--base', 'main', '--json', 'number,headRefOid,title')) : [];
for (const pr of prs) {
  const head = pr.headRefOid;
  const tag = tryGit('rev-parse', '--verify', '--quiet', `refs/tags/approved/${head}`);
  const problems = tag
    ? checkApproval(`refs/approved/${head}`, ZERO, tag)
    : [`No signed approval from the reviewer for ${head.slice(0, 7)} (no tag approved/${head.slice(0, 7)}…).`];
  post(head, 'desk-gate/approval', problems, `Approved: the reviewer's ML-DSA-65 signature on ${head.slice(0, 7)} is valid.`);
}

// Main: every first-parent commit after the planted code, one step at a time.
const tip = tryGit('rev-parse', '--verify', '--quiet', 'refs/heads/main');
if (tip) {
  const chain = git('rev-list', '--first-parent', '--reverse', tip).split('\n');
  for (let i = 1; i < chain.length; i++) {
    const sha = chain[i];
    const subject = git('log', '-1', '--format=%s', sha);
    const problems = checkMain(chain[i - 1], sha);
    post(sha, 'desk-gate/main', problems, /^Ship /.test(subject) ? "Ship signed by the shipper's key, merging an approved commit with nothing added." : "Accepted risk signed by the shipper's key; changes only ACCEPTED-RISKS.md.");
  }
}

const lines = ['## desk-gate', '', '| Commit | Check | Result |', '|---|---|---|'];
for (const r of results) lines.push(`| \`${r.sha.slice(0, 7)}\` | ${r.context} | ${r.state === 'success' ? '✅' : '❌'} ${r.description.replace(/\|/g, '\\|')} |`);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${lines.join('\n')}\n`);
console.log(lines.join('\n'));
// Red only when main itself breaks a rule; an unapproved PR is a normal state
// (it shows ✗ on that PR) and shouldn't fail the whole run.
if (results.some((r) => r.context === 'desk-gate/main' && r.state === 'failure')) process.exit(1);
