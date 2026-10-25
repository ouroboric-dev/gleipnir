#!/opt/ygg/bin/node
// ygg-check-result: converts one check tool's machine output into the factory's typed result, ygg.check/v1 (change
// typed-boundaries, design section 4). A realm's check script runs its tool, keeps the exit code, and calls
//   ygg-check-result --check NAME --exit CODE [--timed-out] --duration-ms N --format FORMAT
//                    [--input FILE]... [--kind KIND --message TEXT]... [--root DIR] [--level LEVEL]
// The result goes to the file named by $YGG_CHECK_RESULT, written whole through a temp file in the same folder and a
// rename. The tool exits 0 once it has written the result, and 2, with the reason on stderr and no result, on any error
// (inputs it cannot read, or a fault of its own): the check script then exits non-zero, which is a realm failure and
// not a finding. A message
// is at most 4000 characters, a finding's claim, and the result at most 768 KiB: failures and passed tests are dropped
// from the end to stay under it, with a note.
//
// Formats: go-test-json, go-vet-json, golangci-json, govulncheck-json, osv-json, sqlc-text, oasdiff-json, vitest-json,
// playwright-json, eslint-json, tsc-text, npm-audit-json, none
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
const MAX_MESSAGE = 4000; // gungnir.MaxClaim: a failure's message becomes a finding's claim
const MAX_DOC = 768 * 1024; // under checks.MaxResult, the most of a result Odin reads
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
  // Lines that are not events (a stray warning, a cut line) are skipped and counted, provided at least one line is an
  // event; a stream with none is not go test -json output at all.
  const events = [];
  let skipped = 0, firstBad;
  for (const { name, text } of inputs) {
    const ls = text.split('\n');
    ls.forEach((l, i) => {
      if (!l.trim()) return;
      try {
        const ev = JSON.parse(l);
        need(isObj(ev), 'not an object');
        events.push(ev);
      } catch (e) {
        skipped++;
        firstBad ??= `${name}: line ${i + 1} is not a go test -json event (${e.message})`;
      }
    });
  }
  if (events.length === 0 && skipped > 0) throw new Refuse(firstBad);
  if (skipped > 0) notes.push(`skipped ${skipped} lines that are not JSON`);
  events.forEach((ev) => {
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
      // A test that began and never ended (a timeout panic, os.Exit, log.Fatal) has no result of its own; the package's
      // failure is the only sign, so each is a failure of its own, with the output it printed.
      const hadTests = p.tests;
      const unfinished = [...tests.values()].filter((t) => t.pkg === ev.Package && t.result === undefined);
      for (const t of unfinished) {
        const id = testId(t.pkg, t.name);
        if (id) { if (failed.has(id)) continue; failed.add(id); }
        p.tests++;
        t.result = 'fail';
        const raw = t.out.join('').split('\n');
        const loc = raw.map((r) => r.match(/^\s*([^\s:]+\.go):(\d+)(?::(\d+))?:/)).find(Boolean);
        const msg = textOf(raw.filter((r) => !/^\s*=== (RUN|PAUSE|CONT|NAME)\b/.test(r))) || 'did not finish';
        failures.push(failure('test', id ? msg : `${t.pkg}.${t.name}: ${msg}`, { test: id, loc: loc && location(loc[1], +loc[2], +loc[3]) }));
      }
      const broken = typeof ev.FailedBuild === 'string' && ev.FailedBuild;
      if (broken || /\[build failed\]/.test(outText)) {
        const src = broken ? (builds.get(ev.FailedBuild) ?? []).join('').split('\n').filter((r) => !r.startsWith('#')) : outText.split('\n').filter((r) => !/^FAIL\t/.test(r));
        const first = src.map((r) => r.match(/^\s*(\S+\.go):(\d+):(\d+):/)).find(Boolean);
        failures.push(failure('build', textOf(src) || `${ev.Package} failed to build`, { loc: first && location(first[1], +first[2], +first[3]) }));
      } else if (hadTests === 0) {
        // Nothing failed on its own account: the package's output, and what the unfinished tests printed.
        const more = unfinished.flatMap((t) => t.out.join('').split('\n'));
        failures.push(failure('test', textOf([...outText.split('\n'), ...more]) || `${ev.Package} failed with no output`));
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
// analyzer may carry {"error": "..."} instead. Locations are made relative to --root, like the web formats.
//
// Up to two inputs, told apart by content: an input is vet's stdout (JSON) when its first line that is not blank
// and not a "# package" header starts with { or [, or when it holds nothing else; any other input is vet's stderr
// text. On a type error vet prints no JSON, only "# package" headers and "vet: file:line:col: message" lines on
// stderr, and exits 1. Each such line (the "vet: " prefix is optional) is a failure of kind "type" with its location
// made relative to --root; headers and any other line are ignored.
const vetPosn = /^(?:vet: )?(\S.*?):(\d+):(\d+): (\S.*)$/;
function goVetJSON(inputs, ctx) {
  const failures = [];
  const rel = (f) => relPath(f, ctx.root).replace(/^\.\//, '');
  for (const { name, text } of inputs) {
    const body = text.split('\n').filter((l) => !l.startsWith('#')).join('\n').trimStart();
    if (body !== '' && body[0] !== '{' && body[0] !== '[') {
      for (const l of text.split('\n')) {
        const m = l.replace(/\r$/, '').match(vetPosn);
        if (m) failures.push(failure('type', m[4], { loc: location(rel(m[1]), +m[2], +m[3]) }));
      }
      continue;
    }
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
            failures.push(failure('lint', `${analyzer}: ${d.message}`, { loc: m ? location(rel(m[1]), +m[2], +m[3]) : undefined }));
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
      // typecheck issues carry a placeholder Pos (line 1, column 0); the real position is the first file:line:col of Text.
      const at = linter === 'typecheck' ? it.Text.match(/([^\s:]+\.go):(\d+)(?::(\d+))?/) : undefined;
      const loc = linter === 'typecheck' ? at && location(at[1], +at[2], +at[3]) : location(pos.Filename, pos.Line, pos.Column);
      failures.push(failure(linter === 'typecheck' ? 'type' : 'lint', `${linter}: ${it.Text}`, { loc }));
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
    need(isObj(doc) && (doc.results === null || Array.isArray(doc.results)), `${name} is not an osv-scanner JSON report (no results list)`);
    for (const r of doc.results ?? []) {
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

// oasdiff breaking --format json: a list of changes, [] when there are none. Every change counts as a failure, whatever
// its level: the realm's go-contract.sh treats any output but [] as breaking.
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

// The web tools. Paths in their output are absolute; --root (default: the working folder) is the folder they are
// made relative to, so that a test id or a location reads the same in every checkout.
const ANSI = /\u001b\[[0-9;]*m/g;
const plain = (s) => String(s).replace(ANSI, '');
const relPath = (p, root) => {
  if (typeof p !== 'string') return p;
  const base = root.endsWith('/') ? root : root + '/';
  return p.startsWith(base) ? p.slice(base.length) : p;
};
const joinId = (parts) => {
  const id = parts.filter((s) => typeof s === 'string' && s !== '').join(' > ');
  return id && [...id].length <= MAX_ID ? id : undefined;
};
const frameRe = /([^\s()]+):(\d+):(\d+)\)?\s*$/;

// vitest run --reporter=json: {"testResults": [{"name": file, "status", "message", "assertionResults": [{"ancestorTitles",
// "title", "status", "failureMessages"}]}]}. A test's id is "file > describe > name", the file relative to the root
// (fullName joins with spaces and cannot be told from a title with spaces); failures[].test has the same form.
// passed_tests holds the assertions with status passed. A file that failed with no failed test of its own (an import
// error, a hook) is one failure with no test id.
function vitestJSON(inputs, ctx) {
  const failures = [], passed = new Set(), failed = new Set();
  let np = 0, nf = 0, ns = 0;
  for (const { name, text } of inputs) {
    const doc = parseJSON(text, name);
    need(isObj(doc) && Array.isArray(doc.testResults), `${name} is not a vitest JSON report (no testResults list)`);
    for (const f of doc.testResults) {
      need(isObj(f) && typeof f.name === 'string' && (f.assertionResults === undefined || Array.isArray(f.assertionResults)), `${name}: a test file entry has no name or assertion list`);
      const file = relPath(f.name, ctx.root);
      let own = 0;
      for (const t of f.assertionResults ?? []) {
        need(isObj(t) && typeof t.title === 'string' && typeof t.status === 'string', `${name}: a test in ${file} has no title or status`);
        const id = joinId([file, ...(Array.isArray(t.ancestorTitles) ? t.ancestorTitles : []), t.title]);
        if (t.status === 'passed') { np++; if (id) passed.add(id); }
        else if (t.status === 'failed') {
          nf++; own++;
          if (id) { if (failed.has(id)) continue; failed.add(id); }
          const msgs = (Array.isArray(t.failureMessages) ? t.failureMessages : []).map(plain);
          // Stack frames are noise in the message; the first frame outside node_modules is the location.
          const body = msgs.map((m) => m.split('\n').filter((l) => !/^\s+at /.test(l)).join('\n')).join('\n\n');
          const frames = msgs.join('\n').split('\n').filter((l) => /^\s+at /.test(l)).map((l) => l.match(frameRe)).filter(Boolean);
          const fr = frames.find((m) => !m[1].includes('node_modules'));
          failures.push(failure('test', id ? body : `${file}: ${t.title}: ${body}`, { test: id, loc: fr && location(relPath(fr[1].replace(/^file:\/\//, ''), ctx.root), +fr[2], +fr[3]) }));
        } else ns++;
      }
      if (f.status === 'failed' && own === 0) failures.push(failure('test', `${file}: ${plain(f.message || 'the test file failed to run')}`));
    }
  }
  for (const id of failed) passed.delete(id);
  return { failures, passedTests: [...passed], counts: { run: np + nf + ns, passed: np, failed: nf, skipped: ns } };
}

// playwright test --reporter=json: {"suites": [{"title": file, "specs": [...], "suites": [describes]}], "errors": []}.
// A spec holds one test per project, each with "results", one per attempt. A test passes when its final attempt
// passed: status "expected", and "flaky" (failed, then passed on a retry), which also gets a note naming it. "unexpected"
// is a failure and "skipped" a skip. The id is "[project] file > describe > name" (the project part only when the
// project has a name), the file as the report gives it, relative to the config's testDir. Errors outside any test (a
// config or import failure) are failures with no test id.
function playwrightJSON(inputs, ctx) {
  const failures = [], passed = new Set(), failed = new Set(), flaky = [];
  let np = 0, nf = 0, ns = 0;
  const errorFailure = (e, prefix) => {
    const msg = plain(isObj(e) ? (e.message ?? e.value ?? 'failed') : 'failed');
    const l = isObj(e) && isObj(e.location) ? e.location : {};
    return failure('test', prefix ? `${prefix}: ${msg}` : msg, { loc: location(relPath(l.file, ctx.root), l.line, l.column) });
  };
  for (const { name, text } of inputs) {
    const doc = parseJSON(text, name);
    need(isObj(doc) && Array.isArray(doc.suites), `${name} is not a Playwright JSON report (no suites list)`);
    const walk = (suite, trail) => {
      need(isObj(suite) && typeof suite.title === 'string', `${name}: a suite has no title`);
      const here = [...trail, suite.title];
      for (const spec of suite.specs ?? []) {
        need(isObj(spec) && typeof spec.title === 'string' && Array.isArray(spec.tests), `${name}: a spec of ${suite.title} has no title or tests`);
        for (const t of spec.tests) {
          need(isObj(t) && typeof t.status === 'string' && Array.isArray(t.results), `${name}: test ${spec.title} has no status or results`);
          const id = joinId([(t.projectName ? `[${t.projectName}] ` : '') + here[0], ...here.slice(1), spec.title]);
          if (t.status === 'expected' || t.status === 'flaky') {
            np++;
            if (id) passed.add(id);
            if (t.status === 'flaky') flaky.push(id ?? spec.title);
          } else if (t.status === 'skipped') ns++;
          else if (t.status === 'unexpected') {
            nf++;
            if (id) { if (failed.has(id)) continue; failed.add(id); }
            const last = t.results[t.results.length - 1];
            const err = isObj(last) ? (last.error ?? (Array.isArray(last.errors) ? last.errors[0] : undefined)) : undefined;
            const f = errorFailure(err ?? { message: `failed with status ${last?.status ?? 'unknown'}` }, id ? '' : `${here.join(' > ')} > ${spec.title}`);
            if (id) f.test = id;
            failures.push(f);
          } else throw new Refuse(`${name}: test ${spec.title} has status ${JSON.stringify(t.status)}, not one of expected, unexpected, flaky, skipped`);
        }
      }
      for (const s of suite.suites ?? []) walk(s, here);
    };
    for (const s of doc.suites) walk(s, []);
    for (const e of Array.isArray(doc.errors) ? doc.errors : []) failures.push(errorFailure(e));
  }
  for (const id of failed) passed.delete(id);
  const notes = flaky.length ? [`Flaky tests (failed, then passed on a retry) count as passed: ${flaky.length}${flaky.length > 10 ? ', the first 10' : ''}: ${flaky.slice(0, 10).join(', ')}.`] : [];
  return { failures, passedTests: [...passed], counts: { run: np + nf + ns, passed: np, failed: nf, skipped: ns }, notes };
}

// eslint -f json: [{"filePath", "messages": [{"ruleId", "severity", "message", "line", "column"}]}]. An error (severity 2,
// which includes a parse error with no rule) is a failure; warnings are counted in a note.
function eslintJSON(inputs, ctx) {
  const failures = [];
  let warnings = 0;
  for (const { name, text } of inputs) {
    const doc = parseJSON(text, name);
    need(Array.isArray(doc), `${name} is not an ESLint JSON report (not a list of files)`);
    for (const f of doc) {
      need(isObj(f) && typeof f.filePath === 'string' && Array.isArray(f.messages), `${name}: a file entry has no filePath or messages`);
      for (const m of f.messages) {
        need(isObj(m) && typeof m.message === 'string' && Number.isInteger(m.severity), `${name}: a message in ${f.filePath} has no text or severity`);
        if (m.severity !== 2) { warnings++; continue; }
        failures.push(failure('lint', `${m.ruleId ? m.ruleId + ': ' : ''}${m.message}`, { loc: location(relPath(f.filePath, ctx.root), m.line, m.column) }));
      }
    }
  }
  return { failures, notes: warnings ? [`${warnings} warnings are not failures; the log has them.`] : [] };
}

// tsc (--pretty false): "file(line,col): error TSnnnn: message", and lines indented under it that continue the message.
// A diagnostic with no file ("error TS5023: ...") has no location. Warnings do not exist in tsc; other lines are counted.
function tscText(inputs, ctx) {
  const failures = [];
  let other = 0;
  for (const { name, text } of inputs) {
    need(!text.includes('\0') && !text.includes('�'), `${name} is not text`);
    let cur;
    const flush = () => {
      if (!cur) return;
      failures.push(failure('type', `${cur.code}: ${textOf([cur.first, ...cur.rest])}`, { loc: cur.loc }));
      cur = undefined;
    };
    for (const l of plain(text).split('\n')) {
      const m = l.match(/^(?:(.+?)\((\d+),(\d+)\): )?error (TS\d+): (.*)$/);
      if (m) {
        flush();
        cur = { code: m[4], first: m[5], rest: [], loc: m[1] && location(relPath(m[1], ctx.root), +m[2], +m[3]) };
      } else if (cur && /^\s+\S/.test(l)) cur.rest.push(l);
      else if (l.trim()) { flush(); other++; }
    }
    flush();
  }
  return { failures, notes: other ? [`${other} lines of tsc output are not diagnostics and are not failures; the log has them.`] : [] };
}

// npm audit --json (report version 2): {"vulnerabilities": {pkg: {"severity", "via": [advisory | "other-package"],
// "fixAvailable"}}}. An advisory is a "via" entry that is an object (a string names the package it came through, whose
// own entry holds the advisory); it is listed once by its source id. One failure per advisory at --level or above;
// the rest are counted in a note. An {"error"} document (the registry could not be reached) is refused: it is a
// realm failure, not a finding.
const SEVERITIES = ['info', 'low', 'moderate', 'high', 'critical'];
function npmAuditJSON(inputs, ctx) {
  const min = SEVERITIES.indexOf(ctx.level);
  const failures = [], seen = new Set();
  let below = 0;
  for (const { name, text } of inputs) {
    const doc = parseJSON(text, name);
    need(isObj(doc), `${name} is not an npm audit JSON report`);
    need(!isObj(doc.error), `${name} is an npm audit error: ${isObj(doc.error) ? (doc.error.summary ?? doc.error.code ?? 'unknown') : ''}`);
    need(isObj(doc.vulnerabilities), `${name} is not an npm audit JSON report (no vulnerabilities map)`);
    for (const [pkg, v] of Object.entries(doc.vulnerabilities)) {
      need(isObj(v) && Array.isArray(v.via), `${name}: ${pkg} has no via list`);
      for (const a of v.via) {
        if (!isObj(a)) continue;
        need(typeof a.title === 'string' && SEVERITIES.includes(a.severity), `${name}: an advisory of ${pkg} has no title or a known severity`);
        const key = a.source ?? `${a.name}\0${a.title}`;
        if (seen.has(key)) continue;
        seen.add(key);
        if (SEVERITIES.indexOf(a.severity) < min) { below++; continue; }
        const fix = v.fixAvailable === false ? ', no fix is available' : isObj(v.fixAvailable) ? `, fix: ${v.fixAvailable.name}@${v.fixAvailable.version}${v.fixAvailable.isSemVerMajor ? ' (major)' : ''}` : v.fixAvailable === true ? ', a fix is available' : '';
        failures.push(failure('scan', `${a.name ?? pkg}: ${a.title} (${a.severity}${a.url ? ', ' + a.url : ''}${a.range ? ', vulnerable ' + a.range : ''}${fix})`));
      }
    }
  }
  return { failures, notes: below ? [`${below} advisories below ${ctx.level} are not failures.`] : [] };
}

const FORMATS = {
  'go-test-json': goTestJSON,
  'go-vet-json': goVetJSON,
  'golangci-json': golangciJSON,
  'govulncheck-json': govulncheckJSON,
  'osv-json': osvJSON,
  'sqlc-text': sqlcText,
  'oasdiff-json': oasdiffJSON,
  'vitest-json': vitestJSON,
  'playwright-json': playwrightJSON,
  'eslint-json': eslintJSON,
  'tsc-text': tscText,
  'npm-audit-json': npmAuditJSON,
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
    if (!['--check', '--exit', '--duration-ms', '--format', '--input', '--kind', '--message', '--root', '--level'].includes(flag)) throw new Refuse(`unknown argument ${flag}`);
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
  need(a.level === undefined || a.format === 'npm-audit-json', '--level is for the npm-audit-json format');
  a.level ??= 'high';
  need(SEVERITIES.includes(a.level), `--level ${a.level} is not one of ${SEVERITIES.join(', ')}`);
  need(a.root === undefined || (a.root.startsWith('/') && a.root.length > 1), '--root needs an absolute folder');
  a.root ??= process.cwd();
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
  else r = FORMATS[a.format](a.inputs.map((f) => ({ name: f, text: readInput(f) })), { timedOut: a.timedOut, root: a.root, level: a.level });
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
  return fit(out, notes.map((n) => clip(n, 4096)));
}

const serialize = (doc) => JSON.stringify(doc, null, 2) + '\n';

// fit returns the result with its notes, under MAX_DOC bytes. A result that is over drops failures and passed tests
// from the end, and says how many in a note: while passed tests wait, failures keep at most half the room, so a
// broad failure keeps both its first findings and the proof a dispute needs; either list takes what the other leaves.
function fit(out, notes) {
  const doc = (ns, k, m) => {
    const d = { ...out, failures: out.failures.slice(0, k) };
    if (out.passed_tests) d.passed_tests = out.passed_tests.slice(0, m);
    if (ns.length) d.notes = ns;
    return d;
  };
  const F = out.failures, P = out.passed_tests ?? [];
  const whole = doc(notes.slice(0, MAX_NOTES), F.length, P.length);
  if (Buffer.byteLength(serialize(whole)) <= MAX_DOC) return whole;
  const kept = notes.slice(0, MAX_NOTES - 1);
  const at = (k, m) => doc([...kept, `dropped ${F.length - k} failures and ${P.length - m} passed tests to stay under 768 KiB`], k, m);
  const fits = (k, m) => Buffer.byteLength(serialize(at(k, m))) <= MAX_DOC;
  // most is how many items of a list fit in n bytes on their own, compact: no more can fit in the document.
  const most = (list, n) => {
    let used = 0, i = 0;
    for (; i < list.length; i++) if ((used += Buffer.byteLength(JSON.stringify(list[i])) + 1) > n) break;
    return i;
  };
  // largest is the largest x in [lo, hi] with ok(x), ok being monotone; lo when none.
  const largest = (lo, hi, ok) => {
    while (lo < hi) {
      const mid = Math.ceil((lo + hi) / 2);
      if (ok(mid)) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  };
  let k = most(F, P.length ? MAX_DOC / 2 : MAX_DOC);
  if (!fits(k, 0)) k = largest(0, k, (x) => fits(x, 0));
  const m = largest(0, most(P, MAX_DOC), (y) => fits(k, y));
  if (m === P.length) k = largest(k, most(F, MAX_DOC), (x) => fits(x, m));
  return at(k, m);
}

function main() {
  const dest = process.env.YGG_CHECK_RESULT;
  need(dest, 'YGG_CHECK_RESULT is not set');
  const doc = build(parseArgs(process.argv.slice(2)));
  const tmp = path.join(path.dirname(dest), `.${path.basename(dest)}.${process.pid}.tmp`);
  try {
    fs.writeFileSync(tmp, serialize(doc), { flag: 'wx', mode: 0o644 });
    fs.renameSync(tmp, dest);
  } catch (e) {
    fs.rmSync(tmp, { force: true });
    throw new Refuse(`cannot write ${dest}: ${e.code ?? e.message}`);
  }
}

// Any error is a refusal, a fault of the converter as much as an input it cannot read: exit 2 and one line of
// reason, never a stack and never a result.
try {
  main();
} catch (e) {
  const why = e instanceof Error ? e.message : String(e);
  process.stderr.write(`ygg-check-result: ${why.replace(/\s+/g, ' ')}\n`);
  process.exit(2);
}
