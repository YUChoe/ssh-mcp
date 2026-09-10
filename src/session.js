import { Client } from 'ssh2';
import { randomUUID } from 'crypto';
import * as store from './store.js';

const MARKER = '__MCP_DONE__';
const ANSI_RE = /\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\r/g;

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
    stream.on('data', c => { this.buf += c.toString(); this._notify(); });
    stream.stderr?.on('data', c => { this.buf += c.toString(); this._notify(); });
    stream.once('close', () => this._settle());
  }

  _notify() {
    const firstNL = this.buf.indexOf('\n');
    const searchFrom = firstNL === -1 ? 0 : firstNL + 1;
    for (let i = this.waiters.length - 1; i >= 0; i--) {
      const w = this.waiters[i];
      if (w.marker) {
        const pos = this.buf.indexOf(w.marker, searchFrom);
        if (pos === -1) continue;
      }
      clearTimeout(w.timer);
      this.waiters.splice(i, 1);
      w.resolve(this._flush(w.marker));
    }
  }

  _settle() {
    this.waiters.forEach(w => { clearTimeout(w.timer); w.resolve(this._flush(null)); });
    this.waiters = [];
  }

  _flush(marker) {
    let out = this.buf;
    if (marker) {
      const firstNL = out.indexOf('\n');
      const searchFrom = firstNL === -1 ? 0 : firstNL + 1;
      const idx = out.indexOf(marker, searchFrom);
      if (idx !== -1) out = out.slice(0, idx);
      const markerIdx = this.buf.indexOf(marker, searchFrom);
      this.buf = markerIdx !== -1 ? this.buf.slice(markerIdx + marker.length) : '';
    } else {
      this.buf = '';
    }
    const clean = out.replace(ANSI_RE, '').replace(/\r/g, '');
    const nl = clean.indexOf('\n');
    return (nl === -1 ? '' : clean.slice(nl + 1)).trimEnd();
  }

  send(text) { this.stream.write(text + '\n'); }

  exec(command, timeoutMs = 30000) {
    return new Promise(resolve => {
      const sentinel = `${MARKER}_${Date.now()}`;
      let quietTimer = null;
      let resolved = false;

      const safeResolve = (val) => {
        if (resolved) return;
        resolved = true;
        clearTimeout(quietTimer);
        this.stream.off('data', onData);
        resolve(val);
      };

      // quiet timer: interactive 명령용 조기 반환 (sentinel 미감지 시만 동작)
      const onData = () => {
        if (resolved) return;
        clearTimeout(quietTimer);
        quietTimer = setTimeout(() => {
          const i = this.waiters.findIndex(w => w.marker === sentinel);
          if (i === -1) return;
          clearTimeout(this.waiters[i].timer);
          this.waiters.splice(i, 1);
          this.stream.write('\x03');
          safeResolve(this._flush(null));
        }, 500);
      };
      this.stream.on('data', onData);

      // 원래 MVP 방식: _notify가 sentinel 감지 시 즉시 resolve
      const timer = setTimeout(() => safeResolve(this._flush(null)), timeoutMs);
      this.waiters.push({ marker: sentinel, resolve: (val) => safeResolve(val), timer });
      this.buf = '';
      this.stream.write(`${command} ; echo ${sentinel}\n`);
      onData();
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
  shell.send('rel');
  await shell.waitQuiet(1500, 10000);
  shell.send(project);
  const output = await shell.waitQuiet(1500, 15000);
  const envOut = await shell.exec('env | grep XN_HOME');
  if (envOut.includes('XN_HOME=')) {
    meta.project = project;
    await store.upsert(id, { project });
  }
  return { output, env: envOut };
}

export async function execCommand(id, command, timeoutMs = 30000) {
  const { shell } = await ensure(id);
  return shell.exec(command, timeoutMs);
}

export async function sendInput(id, input, quietMs = 1000, timeoutMs = 10000) {
  const { shell } = await ensure(id);
  shell.send(input);
  return shell.waitQuiet(quietMs, timeoutMs);
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
