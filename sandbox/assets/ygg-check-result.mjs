#!/usr/bin/env node
// ygg-check-result: converts one check tool's machine output into the factory's typed result, ygg.check/v1 (change
// typed-boundaries, design section 4). A realm's check script runs its tool, keeps the exit code, and calls
//   ygg-check-result --check NAME --exit CODE [--timed-out] --duration-ms N --format FORMAT
//                    [--input FILE]... [--kind KIND --message TEXT]...
// The result goes to the file named by $YGG_CHECK_RESULT, written whole through a temp file in the same folder and a
// rename. The tool exits 0 once it has written the result, and 2, with the reason on stderr and no result, when it
// cannot read its inputs: the check script then exits non-zero, which is a realm failure and not a finding.
//
// Formats: go-test-json, go-vet-json, golangci-json, govulncheck-json, osv-json, sqlc-text, oasdiff-json, none
// (no tool output: the --kind/--message pairs only, for a policy check). Node standard library only; the JSON
// formats are read strictly and a document of another shape is refused.
//
// The exit code stays the truth: passed is true only when the exit is 0, the run did not time out and no failure was
// found. The result never says "passed" against the exit code. Layout in the image: /opt/ygg/bin/ygg-check-result.mjs.
import fs from 'node:fs';
import path from 'node:path';

const MAX_INPUT = 64 * 1024 * 1024;
const MAX_FAILURES = 500;
const MAX_PASSED = 20000;
const MAX_NOTES = 200;
const MAX_MESSAGE = 16384;
const MAX_ID = 1000;
const KINDS = ['test', 'lint', 'type', 'build', 'scan', 'policy', 'other'];

class Refuse extends Error {}

// Text helpers. The schema counts characters, so cuts are made on code points.
const clip = (s, n) => {
  const cps = [...s];
  return cps.length <= n ? s : cps.slice(0, n - 14).join('') + '…[truncated]';
};
const dedent = (lines) => {
  const ind = Math.min(...lines.filter((l) => l.trim()).map((l) => l.match(/^\s*/)[0].length), Infinity);
  return lines.map((l) => l.slice(Number.isFinite(ind) ? ind : 0).trimEnd());
};
const trimBlank = (lines) => {
  let a = 0, b = lines.length;
  while (a < b && !lines[a].trim()) a++;
  while (b > a && !lines[b - 1].trim()) b--;
  return lines.slice(a, b);
};
// A message from raw output lines: no blank edges, no common indent.
const textOf = (lines) => dedent(trimBlank(lines)).join('\n');
const location = (file, line, col) => {
  if (!file || !Number.isInteger(line) || line < 1) return undefined;
  const loc = col > 0 ? `${file}:${line}:${col}` : `${file}:${line}`;
  return /^[^\n\r]+:[0-9]+(:[0-9]+)?$/.test(loc) && [...loc].length <= MAX_ID ? loc : undefined;
};
const failure = (kind, message, { test, loc } = {}) => {
  const f = { kind };
  if (test) f.test = test;
  if (loc) f.location = loc;
  f.message = clip(message.trim() || 'failed', MAX_MESSAGE);
  return f;
};
const testId = (pkg, name) => {
  const id = `${pkg}.${name}`;
  return [...id].length <= MAX_ID ? id : undefined;
};

function parseJSON(text, name) {
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Refuse(`${name} is not JSON (${e.message})`);
  }
}

// Splits text holding JSON values one after another (go vet -json writes one per package, with "# package" lines
// between them) into the values. A value is an object or an array.
function jsonValues(text, name) {
  const out = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { i++; continue; }
    if (c === '#') { while (i < n && text[i] !== '\n') i++; continue; }
    if (c !== '{' && c !== '[') throw new Refuse(`${name} is not JSON: unexpected ${JSON.stringify(c)} at offset ${i}`);
    const start = i;
    let depth = 0, inStr = false;
    for (; i < n; i++) {
      const d = text[i];
      if (inStr) {
        if (d === '\\') i++;
        else if (d === '"') inStr = false;
      } else if (d === '"') inStr = true;
      else if (d === '{' || d === '[') depth++;
      else if (d === '}' || d === ']') { if (--depth === 0) { i++; break; } }
    }
    if (depth !== 0) throw new Refuse(`${name} is not JSON: a value is cut short at offset ${start}`);
    out.push(parseJSON(text.slice(start, i), name));
  }
  return out;
}

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const need = (cond, what) => { if (!cond) throw new Refuse(what); };

// go test -json. One failure per failed test (subtests and their parent each, as Go reports them), one per package
// that failed to build or failed outside any test (a panic, a timeout). passed_tests holds the tests with a pass
// action, as pkg.TestName, the form failures[].test has; a test that failed in any run is never in it.
function goTestJSON(inputs, ctx) {
  const notes = [];
  const tests = new Map(); // "pkg\0name" -> {pkg, name, out, result, subs}
  const pkgs = new Map();
  const builds = new Map();
  const failures = [];
  const failed = new Set(); // test ids that have failed
  const passed = new Set();
  const pkg = (p) => { if (!pkgs.has(p)) pkgs.set(p, { out: [], tests: 0 }); return pkgs.get(p); };
  const key = (p, t) => `${p}\0${t}`;
  const lines = [];
  for (const { name, text } of inputs) text.split('\n').forEach((l, i) => { if (l.trim()) lines.push({ name, n: i + 1, l }); });
  lines.forEach(({ name, n, l }, idx) => {
    let ev;
    try {
      ev = JSON.parse(l);
      need(isObj(ev), 'not an object');
    } catch (e) {
      // A run killed at its time limit may end in half a line; nothing else may.
      if (ctx.timedOut && idx === lines.length - 1) {
        notes.push(`The last line of ${name} was cut by the time limit and is ignored.`);
        return;
      }
      throw new Refuse(`${name}: line ${n} is not a go test -json event (${e.message})`);
    }
    const act = ev.Action;
    if (act === 'build-output') {
      if (typeof ev.ImportPath === 'string') (builds.get(ev.ImportPath) ?? builds.set(ev.ImportPath, []).get(ev.ImportPath)).push(String(ev.Output ?? ''));
      return;
    }
    if (typeof ev.Package !== 'string' || !ev.Package) return;
    const p = pkg(ev.Package);
    if (typeof ev.Test === 'string' && ev.Test) {
      const k = key(ev.Package, ev.Test);
      if (!tests.has(k)) tests.set(k, { pkg: ev.Package, name: ev.Test, out: [], subs: [] });
      const t = tests.get(k);
      if (act === 'run') { t.out = []; t.result = undefined; }
      else if (act === 'output') t.out.push(String(ev.Output ?? ''));
      else if (act === 'pass' || act === 'skip') {
        t.result = act;
        if (act === 'pass') { const id = testId(ev.Package, ev.Test); if (id) passed.add(id); }
      } else if (act === 'fail') {
        t.result = 'fail';
        p.tests++;
        const id = testId(ev.Package, ev.Test);
        // A parent learns of its failed subtests, so that a failure with no output of its own says why.
        for (let cut = ev.Test.lastIndexOf('/'); cut > 0; cut = ev.Test.lastIndexOf('/', cut - 1)) {
          const parent = tests.get(key(ev.Package, ev.Test.slice(0, cut)));
          if (parent) parent.subs.push(ev.Test.slice(cut + 1));
        }
        if (id) { if (failed.has(id)) return; failed.add(id); }
        const raw = t.out.join('').split('\n');
        const loc = raw.map((r) => r.match(/^\s*([^\s:]+\.go):(\d+)(?::(\d+))?:/)).find(Boolean);
        const body = raw.filter((r) => !/^\s*=== (RUN|PAUSE|CONT|NAME)\b/.test(r) && !/^\s*--- (FAIL|PASS|SKIP):/.test(r));
        let msg = textOf(body);
        if (!msg) msg = t.subs.length ? `failed because of its subtests: ${[...new Set(t.subs)].slice(0, 5).join(', ')}` : 'failed with no output';
        if (!id) msg = `${ev.Package}.${ev.Test}: ${msg}`;
        failures.push(failure('test', msg, { test: id, loc: loc && location(loc[1], +loc[2], +loc[3]) }));
      }
      return;
    }
    if (act === 'output') p.out.push(String(ev.Output ?? ''));
    else if (act === 'fail') {
      const outText = p.out.join('');
      const broken = typeof ev.FailedBuild === 'string' && ev.FailedBuild;
      if (broken || /\[build failed\]/.test(outText)) {
        const src = broken ? (builds.get(ev.FailedBuild) ?? []).join('').split('\n').filter((r) => !r.startsWith('#')) : outText.split('\n').filter((r) => !/^FAIL\t/.test(r));
        const first = src.map((r) => r.match(/^\s*(\S+\.go):(\d+):(\d+):/)).find(Boolean);
        failures.push(failure('build', textOf(src) || `${ev.Package} failed to build`, { loc: first && location(first[1], +first[2], +first[3]) }));
      } else if (p.tests === 0) {
        failures.push(failure('test', textOf(outText.split('\n')) || `${ev.Package} failed with no output`));
      }
    }
  });
  for (const id of failed) passed.delete(id);
  let run = 0, np = 0, nf = 0, ns = 0;
  for (const t of tests.values()) {
    if (t.result === 'pass') np++;
    else if (t.result === 'fail') nf++;
    else if (t.result === 'skip') ns++;
  }
  run = np + nf + ns;
  return { failures, passedTests: [...passed], counts: { run, passed: np, failed: nf, skipped: ns }, notes };
}

// go vet -json: {"pkg": {"analyzer": [{"posn": "file:line:col", "message": "..."}]}}, one object per package; an
// analyzer may carry {"error": "..."} instead.
function goVetJSON(inputs) {
  const failures = [];
  for (const { name, text } of inputs) {
    for (const v of jsonValues(text, name)) {
      need(isObj(v), `${name}: a go vet -json value is not an object`);
      for (const [pkg, analyzers] of Object.entries(v)) {
        need(isObj(analyzers), `${name}: package ${pkg} does not map analyzers to findings`);
        for (const [analyzer, found] of Object.entries(analyzers)) {
          if (isObj(found) && typeof found.error === 'string') {
            failures.push(failure('build', `${pkg}: ${analyzer}: ${found.error}`));
            continue;
          }
          need(Array.isArray(found), `${name}: ${pkg}/${analyzer} is not a list of findings`);
          for (const d of found) {
            need(isObj(d) && typeof d.message === 'string', `${name}: a ${analyzer} finding has no message`);
            const m = typeof d.posn === 'string' && d.posn.match(/^(.+):(\d+):(\d+)$/);
            failures.push(failure('lint', `${analyzer}: ${d.message}`, { loc: m ? location(m[1], +m[2], +m[3]) : undefined }));
          }
        }
      }
    }
  }
  return { failures };
}

// golangci-lint run --output.json.path: {"Issues": [{"FromLinter", "Text", "Pos": {"Filename", "Line", "Column"}}], ...}.
function golangciJSON(inputs) {
  const failures = [];
  for (const { name, text } of inputs) {
    const doc = parseJSON(text, name);
    need(isObj(doc) && 'Issues' in doc && (doc.Issues === null || Array.isArray(doc.Issues)), `${name} is not a golangci-lint JSON report (no Issues list)`);
    for (const it of doc.Issues ?? []) {
      need(isObj(it) && typeof it.Text === 'string', `${name}: an issue has no Text`);
      const pos = isObj(it.Pos) ? it.Pos : {};
      const linter = typeof it.FromLinter === 'string' && it.FromLinter ? it.FromLinter : 'golangci-lint';
      failures.push(failure(linter === 'typecheck' ? 'type' : 'lint', `${linter}: ${it.Text}`, { loc: location(pos.Filename, pos.Line, pos.Column) }));
    }
  }
  return { failures };
}

// govulncheck -json: a stream of {config}, {progress}, {osv}, {finding}. A finding whose first trace frame names a
// function is a vulnerability the code calls: one failure per advisory. The others (a module or package that is
// required but not called) are counted in a note and are not failures, as in govulncheck's own text mode.
function govulncheckJSON(inputs) {
  const osvs = new Map();
  const called = new Map();
  let uncalled = new Set();
  for (const { name, text } of inputs) {
    const msgs = jsonValues(text, name);
    need(msgs.length > 0 && msgs.every(isObj), `${name} holds no govulncheck -json messages`);
    need(msgs.some((m) => isObj(m.config)), `${name} has no govulncheck config message`);
    for (const m of msgs) {
      if (isObj(m.osv) && typeof m.osv.id === 'string') osvs.set(m.osv.id, m.osv);
      if (!isObj(m.finding)) continue;
      const f = m.finding;
      need(typeof f.osv === 'string' && Array.isArray(f.trace) && f.trace.length > 0, `${name}: a finding has no osv id or trace`);
      if (f.trace[0].function) {
        if (!called.has(f.osv)) called.set(f.osv, f);
      } else uncalled.add(f.osv);
    }
  }
  const failures = [];
  for (const [id, f] of called) {
    const top = f.trace[0], site = f.trace[f.trace.length - 1];
    const summary = osvs.get(id)?.summary;
    const where = `${top.module}${top.version ? '@' + top.version : ''}`;
    const fix = f.fixed_version ? `, fixed in ${f.fixed_version}` : ', no fix is known';
    const pos = isObj(site.position) ? site.position : {};
    failures.push(failure('scan', `${id}${summary ? ': ' + summary : ''} (${where}${top.package ? ', ' + top.package + '.' + top.function : ''}${fix})`,
      { loc: location(pos.filename, pos.line, pos.column) }));
  }
  uncalled = [...uncalled].filter((id) => !called.has(id));
  const notes = uncalled.length ? [`${uncalled.length} vulnerabilities in required modules or packages are not called by the code: ${uncalled.slice(0, 10).join(', ')}.`] : [];
  return { failures, notes };
}

// osv-scanner --format json: {"results": [{"source": {...}, "packages": [{"package": {name, version}, "vulnerabilities": [...],
// "groups": [{"ids": [...]}]}]}]}. A group is one vulnerability under several names; each is one failure.
function osvJSON(inputs) {
  const failures = [];
  for (const { name, text } of inputs) {
    const doc = parseJSON(text, name);
    need(isObj(doc) && Array.isArray(doc.results), `${name} is not an osv-scanner JSON report (no results list)`);
    for (const r of doc.results) {
      need(isObj(r) && Array.isArray(r.packages ?? []), `${name}: a result has no packages list`);
      for (const p of r.packages ?? []) {
        need(isObj(p) && isObj(p.package) && typeof p.package.name === 'string', `${name}: a package entry has no package name`);
        const vulns = new Map((p.vulnerabilities ?? []).map((v) => [v.id, v]));
        const groups = Array.isArray(p.groups) && p.groups.length ? p.groups.map((g) => g.ids ?? []) : [...vulns.keys()].map((id) => [id]);
        const at = `${p.package.name}${p.package.version ? '@' + p.package.version : ''}`;
        for (const ids of groups) {
          const lead = ids.find((id) => vulns.has(id)) ?? ids[0];
          need(typeof lead === 'string', `${name}: a vulnerability group of ${at} is empty`);
          const v = vulns.get(lead);
          const also = ids.filter((id) => id !== lead);
          failures.push(failure('scan', `${at}: ${lead}${v?.summary ? ' ' + v.summary : ''}${also.length ? ` (also ${also.join(', ')})` : ''}`));
        }
      }
    }
  }
  return { failures };
}

// sqlc: file:line:col: message, one problem a line. Other lines (headers, a diff) are not failures; a note counts them.
function sqlcText(inputs) {
  const failures = [];
  let other = 0;
  for (const { name, text } of inputs) {
    need(!text.includes('\0') && !text.includes('�'), `${name} is not text`);
    for (const l of text.split('\n')) {
      if (!l.trim() || l.startsWith('#')) continue;
      const m = l.match(/^([^\s:][^:]*):(\d+):(?:(\d+):)?\s+(.+)$/);
      if (m) failures.push(failure('build', m[4], { loc: location(m[1], +m[2], +m[3]) }));
      else other++;
    }
  }
  return { failures, notes: other ? [`${other} lines of sqlc output had no file:line:col and are not failures; the log has them.`] : [] };
}

// oasdiff breaking --format json: a list of changes, [] when there are none.
function oasdiffJSON(inputs) {
  const failures = [];
  for (const { name, text } of inputs) {
    const doc = parseJSON(text, name);
    need(doc === null || Array.isArray(doc), `${name} is not an oasdiff JSON list of changes`);
    for (const c of doc ?? []) {
      need(isObj(c) && typeof c.text === 'string', `${name}: a change has no text`);
      const op = [c.operation, c.path].filter((s) => typeof s === 'string' && s).join(' ');
      failures.push(failure('policy', `${op ? op + ': ' : ''}${c.text}${c.id ? ` (${c.id})` : ''}`));
    }
  }
  return { failures };
}

const FORMATS = {
  'go-test-json': goTestJSON,
  'go-vet-json': goVetJSON,
  'golangci-json': golangciJSON,
  'govulncheck-json': govulncheckJSON,
  'osv-json': osvJSON,
  'sqlc-text': sqlcText,
  'oasdiff-json': oasdiffJSON,
};

function readInput(file) {
  let fd;
  try {
    fd = fs.openSync(file, 'r');
    const st = fs.fstatSync(fd);
    need(st.isFile(), `${file} is not a regular file`);
    need(st.size <= MAX_INPUT, `${file} is over ${MAX_INPUT} bytes`);
    const chunks = [];
    let total = 0;
    const buf = Buffer.allocUnsafe(1 << 20);
    for (;;) {
      const n = fs.readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      total += n;
      need(total <= MAX_INPUT, `${file} is over ${MAX_INPUT} bytes`);
      chunks.push(Buffer.from(buf.subarray(0, n)));
    }
    return Buffer.concat(chunks).toString('utf8').replace(/^﻿/, '');
  } catch (e) {
    if (e instanceof Refuse) throw e;
    throw new Refuse(`cannot read ${file}: ${e.code ?? e.message}`);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function parseArgs(argv) {
  const a = { inputs: [], pairs: [], timedOut: false };
  let kind;
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === '--timed-out') { a.timedOut = true; continue; }
    if (!['--check', '--exit', '--duration-ms', '--format', '--input', '--kind', '--message'].includes(flag)) throw new Refuse(`unknown argument ${flag}`);
    need(i + 1 < argv.length, `${flag} needs a value`);
    const v = argv[++i];
    if (flag === '--input') a.inputs.push(v);
    else if (flag === '--kind') {
      need(kind === undefined, `--kind ${kind} has no --message`);
      need(KINDS.includes(v), `--kind ${v} is not one of ${KINDS.join(', ')}`);
      kind = v;
    } else if (flag === '--message') {
      need(kind !== undefined, '--message needs a --kind before it');
      a.pairs.push([kind, v]);
      kind = undefined;
    } else a[flag.slice(2).replace(/-(.)/g, (_, c) => c.toUpperCase())] = v;
  }
  need(kind === undefined, `--kind ${kind} has no --message`);
  need(typeof a.check === 'string' && a.check && [...a.check].length <= 200, '--check needs a name of 1 to 200 characters');
  need(/^-?\d+$/.test(a.exit ?? ''), '--exit needs an integer');
  need(/^\d+$/.test(a.durationMs ?? ''), '--duration-ms needs a non-negative integer');
  a.exit = Number(a.exit);
  a.durationMs = Number(a.durationMs);
  need(Number.isSafeInteger(a.exit) && Number.isSafeInteger(a.durationMs), '--exit and --duration-ms must be safe integers');
  need(a.format === 'none' || a.format in FORMATS, `--format ${a.format} is not one of ${[...Object.keys(FORMATS), 'none'].join(', ')}`);
  if (a.format === 'none') need(a.inputs.length === 0, 'the none format takes no --input');
  else {
    need(a.inputs.length > 0, `--format ${a.format} needs at least one --input`);
    need(a.pairs.length === 0, `--kind and --message are for the none format`);
  }
  return a;
}

function build(a) {
  let r;
  if (a.format === 'none') r = { failures: a.pairs.map(([kind, message]) => failure(kind, message)) };
  else r = FORMATS[a.format](a.inputs.map((f) => ({ name: f, text: readInput(f) })), { timedOut: a.timedOut });
  const notes = [...(r.notes ?? [])];
  const found = r.failures.length;
  // Passed follows the exit code. A tool that exits 0 while its output shows failures contradicts itself; the result
  // then says passed: false with the failures, deliberately, so that Odin refuses it as contradicting the exit code
  // and the contradiction is seen, not averaged away. A non-zero exit with nothing found is passed: false with an
  // empty list, which the check's caller turns into a finding of its own.
  const passed = a.exit === 0 && !a.timedOut && found === 0;
  if (a.exit === 0 && found > 0) notes.push(`The tool exited 0 but its output shows ${found} failures.`);
  if (a.exit !== 0 && found === 0 && !a.timedOut) notes.push(`The tool exited ${a.exit} and its output shows no failure.`);
  if (a.timedOut) notes.push('The check timed out.');
  const out = { check: a.check, passed, exit_code: a.exit, timed_out: a.timedOut, duration_ms: a.durationMs };
  if (r.counts) out.counts = r.counts;
  out.failures = r.failures.slice(0, MAX_FAILURES);
  if (found > MAX_FAILURES) notes.push(`${found} failures were found; the first ${MAX_FAILURES} are listed.`);
  if (r.passedTests?.length) {
    out.passed_tests = r.passedTests.slice(0, MAX_PASSED);
    if (r.passedTests.length > MAX_PASSED) notes.push(`${r.passedTests.length} tests passed; the first ${MAX_PASSED} are listed.`);
  }
  if (notes.length) out.notes = notes.slice(0, MAX_NOTES).map((n) => clip(n, 4096));
  return out;
}

function main() {
  const dest = process.env.YGG_CHECK_RESULT;
  need(dest, 'YGG_CHECK_RESULT is not set');
  const doc = build(parseArgs(process.argv.slice(2)));
  const tmp = path.join(path.dirname(dest), `.${path.basename(dest)}.${process.pid}.tmp`);
  try {
    fs.writeFileSync(tmp, JSON.stringify(doc, null, 2) + '\n', { flag: 'wx', mode: 0o644 });
    fs.renameSync(tmp, dest);
  } catch (e) {
    fs.rmSync(tmp, { force: true });
    throw new Refuse(`cannot write ${dest}: ${e.code ?? e.message}`);
  }
}

try {
  main();
} catch (e) {
  if (!(e instanceof Refuse)) throw e;
  process.stderr.write(`ygg-check-result: ${e.message}\n`);
  process.exit(2);
}
