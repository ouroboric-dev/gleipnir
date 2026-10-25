#!/opt/ygg/bin/node
// ygg-submit: the stdio MCP server through which a session hands back its typed output (change typed-boundaries,
// design section 3). The agent CLI starts it as a child process inside the work container, with the agent's own
// rights and no network. It offers two tools:
//   submit  {output: object (or a string holding one)} | {file: string}  checks the output against $YGG_OUTPUT_CONTRACT: "accepted", or the errors
//   check   {file: string}                     checks a draft under out/ the same way
// It writes nothing, ever: Odin takes the document from the session's tool call and validates it again, so this
// tool only helps the model repair in-session and is never trusted. The file form reads a regular file under the
// session's working directory's out/ and nothing else.
//
// Layout in the image: /opt/ygg/bin/ygg-submit (this file), /opt/ygg/lib/ygg-submit/node_modules/ajv, /opt/ygg/schemas.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';

const PROTOCOL = '2025-06-18';
const MAX_FILE = 4 * 1024 * 1024;
const MAX_ERRORS = 50;
const SCHEMA_BASE = 'https://github.com/ouroboric-dev/gungnir/schema/';
const here = path.dirname(fileURLToPath(import.meta.url));

// The contracts a session can submit and their schema files: gungnir's schema.Contracts(), each by its exact id (a
// test keeps the two equal). Another version, or a schema that is no contract, is refused.
const CONTRACTS = {
  'ygg.design/v1': 'design.schema.json',
  'ygg.spec/v1': 'spec.schema.json',
  'ygg.conformance/v1': 'conformance.schema.json',
  'ygg.plan/v1': 'plan.schema.json',
  'ygg.reuse-review/v1': 'reuse-review.schema.json',
  'ygg.review/v1': 'review.schema.json',
  'ygg.implement/v1': 'implement.schema.json',
  'ygg.check/v1': 'check.schema.json',
  'ygg.retro/v1': 'retro.schema.json',
  'ygg.decisions/v1': 'decisions.schema.json',
  'ygg.judgement/v1': 'judgement.schema.json',
  'ygg.run-record/v1': 'run-record.schema.json',
};

const TOOLS = [
  {
    name: 'submit',
    description: 'Hand back your output. Give exactly one of output (the object itself) or file (a draft file under out/). ' +
      'It answers "accepted", or the errors to fix and submit again. It writes nothing.',
    inputSchema: {
      type: 'object',
      properties: {
        output: { type: 'object', description: 'The output document, inline.' },
        file: { type: 'string', description: 'A draft under out/, relative to the working directory (at most 4 MiB).' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'check',
    description: 'Check a draft of your output, a file under out/, without handing it back. It answers "accepted" or the errors. It writes nothing.',
    inputSchema: {
      type: 'object',
      properties: { file: { type: 'string', description: 'A draft under out/, relative to the working directory (at most 4 MiB).' } },
      required: ['file'],
      additionalProperties: false,
    },
  },
];

// A refusal the model can act on: it goes back as the tool's result with isError set.
class Refusal extends Error {}

let validators; // contract id -> validate function, built on first use

async function load() {
  const mod = await import(pathToFileURL(path.join(here, '..', 'lib', 'ygg-submit', 'node_modules', 'ajv', 'dist', '2020.js')).href);
  const Ajv2020 = mod.default;
  // allErrors lists every error, as gungnir does. strict is off because the schemas' `if {required}` and `then`
  // subschemas carry no `type`, which ajv's strictTypes would refuse. Patterns run with the u flag (ajv's default
  // unicodeRegExp), and the schemas spell out their character classes because \s differs between Go and JS.
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const dir = path.join(here, '..', 'schemas');
  for (const name of fs.readdirSync(dir).filter((n) => n.endsWith('.schema.json')).sort()) {
    ajv.addSchema(JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8')));
  }
  return (contract) => {
    const v = Object.hasOwn(CONTRACTS, contract) && ajv.getSchema(`${SCHEMA_BASE}${CONTRACTS[contract]}`);
    if (!v) throw new Refusal(`${contract || '(unset)'} is not a contract this session can submit`);
    return v;
  };
}

function at(p) { return p === '' ? '(document)' : p; }

function sentence(e) {
  const p = e.instancePath;
  switch (e.keyword) {
    case 'required':
      return p === '' ? `(document): the property ${e.params.missingProperty} is required` : `${p}/${esc(e.params.missingProperty)}: is required`;
    case 'additionalProperties':
      return p === '' ? `(document): the property ${e.params.additionalProperty} is not allowed` : `${p}/${esc(e.params.additionalProperty)}: is not allowed`;
    case 'enum':
      return `${at(p)}: ${e.message}: ${e.params.allowedValues.join(', ')}`;
    default:
      return `${at(p)}: ${e.message}`;
  }
}

function esc(s) { return String(s).replaceAll('~', '~0').replaceAll('/', '~1'); }

function sortedDistinct(list) {
  return [...new Set(list)].sort().slice(0, MAX_ERRORS);
}

// The rules the JSON Schema cannot say, which gungnir keeps in the Check methods of its Go types. They run only
// on a document the schema accepts.
function dupIds(list, where, what, tail = '') {
  const errors = [];
  const seen = new Set();
  (list ?? []).forEach((x, i) => {
    if (seen.has(x.id)) errors.push(`${where}/${i}/id: ${what} ${x.id} is used twice${tail}`);
    seen.add(x.id);
  });
  return errors;
}

const RULES = {
  'ygg.check/v1': (d) => {
    const passed = new Set(d.passed_tests ?? []);
    const errors = [];
    (d.failures ?? []).forEach((f, i) => {
      if (f.test !== undefined && f.test !== '' && passed.has(f.test)) errors.push(`/failures/${i}/test: the test ${f.test} is listed as passed and as failed`);
    });
    return errors;
  },
  'ygg.design/v1': (d) => dupIds(d.open_questions, '/open_questions', 'the open question id'),
  'ygg.review/v1': (d) => dupIds(d.findings, '/findings', 'the finding id'),
  'ygg.implement/v1': (d) => dupIds(d.disputes, '/disputes', 'the finding id', ' in the disputes: a finding is disputed once'),
  'ygg.decisions/v1': (d) => {
    const errors = dupIds(d.decisions, '/decisions', 'the decision id');
    if (!(d.decisions?.length) && !(d.answers?.length) && !d.reason) errors.push('(document): the file holds no decision, no answer and no reason');
    return errors;
  },
};

async function verdict(doc) {
  const contract = process.env.YGG_OUTPUT_CONTRACT ?? '';
  validators ??= await load();
  const validate = validators(contract);
  let errors;
  if (validate(doc)) errors = (RULES[contract]?.(doc)) ?? [];
  else errors = (validate.errors ?? []).filter((e) => e.keyword !== 'if').map(sentence);
  if (errors.length === 0) return { text: `accepted: the document is a valid ${contract}` };
  errors = sortedDistinct(errors);
  return { error: true, text: `${contract}: the document breaks its contract.\n${errors.join('\n')}` };
}

function parseDocument(text) {
  let doc;
  try { doc = JSON.parse(text); } catch (e) { throw new Refusal(`(document) is not one JSON document: ${e.message}`); }
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) throw new Refusal('(document) must be a JSON object');
  return doc;
}

// parseOutputString reads an output given as a string: it must hold exactly one JSON object, and the refusal says what it held.
function parseOutputString(s) {
  const shown = s.length > 80 ? `${s.slice(0, 80)}...` : s;
  let doc;
  try { doc = JSON.parse(s); } catch (e) { throw new Refusal(`output is a string that does not hold one JSON object: ${e.message} (it starts: ${shown})`); }
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
    const kind = doc === null ? 'null' : Array.isArray(doc) ? 'an array' : typeof doc;
    throw new Refusal(`output is a string that does not hold one JSON object: it holds ${kind} (it starts: ${shown})`);
  }
  return doc;
}

// readDraft reads a draft under out/ in the session's working directory: no absolute path, no .. segment, no
// symlink on any segment, a regular file of at most 4 MiB.
function readDraft(file) {
  if (typeof file !== 'string' || file === '') throw new Refusal('file must be the path of a draft under out/');
  if (file.includes('\0') || path.isAbsolute(file)) throw new Refusal('file must be relative to the working directory');
  if (file.endsWith('/')) throw new Refusal('file must name a file');
  const segs = file.split('/').filter((s) => s !== '' && s !== '.');
  if (segs.includes('..')) throw new Refusal('file may not hold a .. segment');
  if (segs.length < 2 || segs[0] !== 'out') throw new Refusal('file must be a draft under out/');
  let p = process.cwd();
  for (const seg of segs) {
    p = path.join(p, seg);
    let st;
    try { st = fs.lstatSync(p); } catch { throw new Refusal(`${file} does not exist`); }
    if (st.isSymbolicLink()) throw new Refusal(`${file} goes through a symbolic link, which is refused`);
    if (seg === segs[segs.length - 1] && !st.isFile()) throw new Refusal(`${file} is not a regular file`);
  }
  let fd;
  try {
    // O_NONBLOCK: a FIFO swapped in after the lstat must not stop the server.
    fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    // The opened file must sit under the real out/: a directory swapped for a link after the lstat is caught here.
    const opened = fs.readlinkSync(`/proc/self/fd/${fd}`);
    if (!opened.startsWith(path.join(fs.realpathSync(process.cwd()), 'out') + path.sep)) throw new Refusal(`${file} is not under out/`);
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw new Refusal(`${file} is not a regular file`);
    if (st.size > MAX_FILE) throw new Refusal(`${file} is ${st.size} bytes, over the limit of ${MAX_FILE}`);
    const buf = Buffer.alloc(st.size);
    let n = 0;
    while (n < st.size) {
      const r = fs.readSync(fd, buf, n, st.size - n, n);
      if (r === 0) break;
      n += r;
    }
    return buf.subarray(0, n).toString('utf8');
  } catch (e) {
    if (e instanceof Refusal) throw e;
    throw new Refusal(`${file} can't be read: ${e.code ?? e.message}`);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

async function callTool(name, args) {
  const keys = Object.keys(args);
  const only = (...allowed) => {
    const extra = keys.filter((k) => !allowed.includes(k));
    if (extra.length) throw new Refusal(`unknown argument ${extra.join(', ')}`);
  };
  let doc;
  if (name === 'check') {
    only('file');
    if (!('file' in args)) throw new Refusal('check needs file');
    doc = parseDocument(readDraft(args.file));
  } else {
    only('output', 'file');
    if (('output' in args) === ('file' in args)) throw new Refusal('submit takes output or file, one of them');
    if ('file' in args) doc = parseDocument(readDraft(args.file));
    else {
      doc = args.output;
      // A model may pass the object as a JSON string (the probe saw Claude Code do it): exactly one JSON object.
      if (typeof doc === 'string') doc = parseOutputString(doc);
      if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) throw new Refusal('output must be a JSON object');
    }
  }
  return verdict(doc);
}

function reply(id, body) { process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, ...body }) + '\n'); }
function fail(id, code, message) { reply(id, { error: { code, message } }); }

async function handle(line) {
  let req;
  try { req = JSON.parse(line); } catch { return fail(null, -32700, 'parse error'); }
  if (req === null || typeof req !== 'object' || Array.isArray(req) || typeof req.method !== 'string') return fail(req?.id ?? null, -32600, 'invalid request');
  const { id, method } = req;
  if (id === undefined) return; // a notification gets no answer
  switch (method) {
    case 'initialize':
      return reply(id, { result: { protocolVersion: PROTOCOL, capabilities: { tools: {} }, serverInfo: { name: 'ygg', version: '1.0.0' } } });
    case 'ping':
      return reply(id, { result: {} });
    case 'tools/list':
      return reply(id, { result: { tools: TOOLS } });
    case 'tools/call': {
      const p = req.params;
      const tool = p && TOOLS.find((t) => t.name === p.name);
      if (!tool) return fail(id, -32602, `unknown tool ${JSON.stringify(p?.name)}`);
      const args = p.arguments ?? {};
      if (typeof args !== 'object' || Array.isArray(args) || args === null) return fail(id, -32602, 'arguments must be an object');
      try {
        const r = await callTool(tool.name, args);
        return reply(id, { result: { content: [{ type: 'text', text: r.text }], ...(r.error ? { isError: true } : {}) } });
      } catch (e) {
        if (!(e instanceof Refusal)) throw e;
        return reply(id, { result: { content: [{ type: 'text', text: e.message }], isError: true } });
      }
    }
    default:
      return fail(id, -32601, `method not found: ${method}`);
  }
}

// broken answers a request that hit an internal fault, so that the client is never left waiting: a tool result
// that says the tool is broken, or a JSON-RPC internal error. A notification gets nothing.
function broken(line, e) {
  let req;
  try { req = JSON.parse(line); } catch { return; }
  if (req === null || typeof req !== 'object' || req.id === undefined) return;
  const message = `ygg-submit is broken: ${e?.message ?? e}`;
  if (req.method === 'tools/call') reply(req.id, { result: { content: [{ type: 'text', text: message }], isError: true } });
  else fail(req.id, -32603, message);
}

// One request at a time, in order; the server ends when its input does.
let queue = Promise.resolve();
readline.createInterface({ input: process.stdin, crlfDelay: Infinity }).on('line', (line) => {
  if (line.trim() === '') return;
  queue = queue.then(() => handle(line)).catch((e) => {
    process.stderr.write(`ygg-submit: ${e.stack ?? e}\n`);
    broken(line, e);
  });
});
