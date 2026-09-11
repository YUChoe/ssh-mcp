import { Client } from 'ssh2';
import { randomUUID } from 'crypto';
import * as store from './store.js';

const MARKER = '__MCP_DONE__';
const ANSI_RE = /\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\r/g;

// 셸 인자를 단일 인용한다 (csh/sh 공용). 개행과 !(csh history 치환)는 안전하게 인용할 수 없어 거부한다
export function shellQuote(arg) {
  if (/[\r\n!]/.test(arg)) throw new Error(`unsupported character in shell argument: ${JSON.stringify(arg)}`);
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}

const LEGACY = {
  kex: ['diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1', 'ecdh-sha2-nistp256'],
  cipher: ['aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', '3des-cbc'],
  serverHostKey: ['ssh-rsa', 'ssh-dss', 'ecdsa-sha2-nistp256'],
  hmac: ['hmac-sha2-256', 'hmac-sha1'],
};

class Shell {
  constructor(stream) {
    this.stream = stream;
    this.buf = '';
    this.waiters = [];
    this.queue = Promise.resolve(); // 같은 세션의 명령을 순차 실행한다 (공유 버퍼 보호)
    stream.on('data', c => { this.buf += c.toString(); this._notify(); });
    stream.stderr?.on('data', c => { this.buf += c.toString(); this._notify(); });
    stream.once('close', () => this._settle());
  }

  _notify() {
    for (let i = this.waiters.length - 1; i >= 0; i--) {
      const w = this.waiters[i];
      if (this.buf.indexOf(w.marker) === -1) continue;
      clearTimeout(w.timer);
      this.waiters.splice(i, 1);
      w.resolve(this._flush(w));
    }
  }

  _settle() {
    this.waiters.forEach(w => { clearTimeout(w.timer); w.resolve(this._flush(w)); });
    this.waiters = [];
  }

  // 버퍼에서 명령 출력만 추출한다.
  // tty echo 줄(echoMark 포함)까지 버리고, 출력 sentinel(marker) 직전까지를 반환한다.
  // echo 줄 앞에 남아 있던 이전 명령의 잔여 출력(프롬프트 등)도 함께 제거된다.
  _flush({ marker, echoMark }) {
    let out = this.buf;
    this.buf = '';
    const end = out.indexOf(marker);
    if (end !== -1) out = out.slice(0, end);
    const e = out.indexOf(echoMark);
    if (e !== -1) {
      const nl = out.indexOf('\n', e);
      out = nl === -1 ? '' : out.slice(nl + 1);
    }
    return out.replace(ANSI_RE, '').trimEnd();
  }

  send(text) { this.stream.write(text + '\n'); }

  // 큐에 넣어 순차 실행한다. 앞 작업의 실패는 뒤 작업에 전파하지 않는다
  enqueue(fn) {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => {});
    return run;
  }

  // sentinel 수신 또는 timeoutMs 까지 대기한다. 타임아웃 시 Ctrl-C 로 명령을 중단하고 부분 출력을 반환한다.
  // sentinel 은 명령에서 따옴표로 분할해 보내므로 tty echo 줄에는 리터럴이 나타나지 않는다.
  exec(command, timeoutMs = 30000) {
    return new Promise(resolve => {
      const ts = Date.now();
      const w = {
        marker: `${MARKER}_${ts}`,
        echoMark: `echo ${MARKER}"_"${ts}`,
        resolve: output => resolve({ output, timedOut: false }),
      };
      w.timer = setTimeout(() => {
        const i = this.waiters.indexOf(w);
        if (i !== -1) this.waiters.splice(i, 1);
        this.stream.write('\x03');
        resolve({ output: this._flush(w), timedOut: true });
      }, timeoutMs);
      this.waiters.push(w);
      this.buf = '';
      this.stream.write(`${command} ; ${w.echoMark}\n`);
    });
  }

  waitQuiet(quietMs = 1000, timeoutMs = 10000) {
    return new Promise(resolve => {
      let quietTimer = null;
      this.buf = '';
      const flush = () => {
        clearTimeout(quietTimer);
        clearTimeout(globalTimer);
        this.stream.off('data', handler);
        resolve(this.buf.replace(ANSI_RE, '').replace(/\r/g, '').trimEnd());
      };
      const handler = () => { clearTimeout(quietTimer); quietTimer = setTimeout(flush, quietMs); };
      this.stream.on('data', handler);
      const globalTimer = setTimeout(flush, timeoutMs);
      quietTimer = setTimeout(flush, quietMs);
    });
  }
}

// id → { conn, shell, meta }
const active = new Map();

async function openConnection(meta) {
  const { host, port, username, password, privateKey } = meta;
  const conn = new Client();
  await new Promise((res, rej) => {
    const opts = { host, port, username, algorithms: LEGACY, hostVerifier: () => true };
    if (password) opts.password = password;
    if (privateKey) opts.privateKey = privateKey;
    conn.once('ready', res).once('error', rej);
    conn.connect(opts);
  });
  const stream = await new Promise((res, rej) =>
    conn.shell({ term: 'vt100', cols: 220, rows: 50 }, (e, s) => e ? rej(e) : res(s))
  );
  const shell = new Shell(stream);
  await shell.waitQuiet(1000, 5000);
  return { conn, shell };
}

async function restoreState(shell, meta) {
  if (meta.yuviewDone && meta.viewScript) {
    shell.send(meta.viewScript);
    await shell.waitQuiet(1000, 8000);
  }
  if (meta.project) {
    shell.send('rel');
    await shell.waitQuiet(1500, 10000);
    shell.send(meta.project);
    await shell.waitQuiet(1500, 15000);
  }
}

export async function ensure(id) {
  if (active.has(id)) return active.get(id);

  const meta = store.get(id);
  if (!meta) throw new Error(`session not found: ${id}`);

  const { conn, shell } = await openConnection(meta);
  await restoreState(shell, meta);

  const entry = { conn, shell, meta };
  active.set(id, entry);
  conn.once('close', () => active.delete(id));
  conn.once('error', () => active.delete(id));
  return entry;
}

export async function createSession(opts) {
  const id = randomUUID();
  const meta = {
    host: opts.host,
    port: opts.port ?? 22,
    username: opts.username,
    password: opts.password ?? null,
    privateKey: opts.privateKey ?? null,
    viewScript: opts.viewScript,
    yuviewDone: false,
    project: null,
  };
  await store.upsert(id, meta);

  const { conn, shell } = await openConnection(meta);
  const entry = { conn, shell, meta };
  active.set(id, entry);
  conn.once('close', () => active.delete(id));
  conn.once('error', () => active.delete(id));

  shell.send(meta.viewScript);
  const output = await shell.waitQuiet(1000, 8000);
  meta.yuviewDone = true;
  await store.upsert(id, { yuviewDone: true });

  return { id, output };
}

export async function setProject(id, project) {
  const { shell, meta } = await ensure(id);
  return shell.enqueue(async () => {
    shell.send('rel');
    await shell.waitQuiet(1500, 10000);
    shell.send(project);
    const output = await shell.waitQuiet(1500, 15000);
    const { output: envOut } = await shell.exec('env | grep XN_HOME');
    if (envOut.includes('XN_HOME=')) {
      meta.project = project;
      await store.upsert(id, { project });
    }
    return { output, env: envOut };
  });
}

// 반환: { output, timedOut }
export async function execCommand(id, command, timeoutMs = 30000) {
  const { shell } = await ensure(id);
  return shell.enqueue(() => shell.exec(command, timeoutMs));
}

export async function sendInput(id, input, quietMs = 1000, timeoutMs = 10000) {
  const { shell } = await ensure(id);
  return shell.enqueue(() => { shell.send(input); return shell.waitQuiet(quietMs, timeoutMs); });
}

export function listSessions() {
  return Object.entries(store.all()).map(([id, meta]) => ({
    id,
    host: meta.host,
    username: meta.username,
    project: meta.project ?? null,
    yuviewDone: meta.yuviewDone,
    connected: active.has(id),
  }));
}

export async function closeSession(id) {
  const entry = active.get(id);
  if (entry) { entry.shell.stream.end(); entry.conn.end(); active.delete(id); }
  await store.remove(id);
}

export function getConn(id) {
  return active.get(id)?.conn ?? null;
}
