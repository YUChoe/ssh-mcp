import { Client } from 'ssh2';
import { randomUUID } from 'crypto';
import path from 'path';
import * as store from './store.js';
import { verifyHostKey } from './knownhosts.js';
import { KNOWN_HOSTS_PATH } from './paths.js';

const MARKER = '__MCP_DONE__';
const ANSI_RE = /\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\r/g;
// rel(Rel_Version) 메뉴의 마지막 블록: "--- Click a Version or Enter to <기본값> ---" 줄과 이어지는 대시 줄
const REL_PROMPT = /Enter to [^\n]*\n-+\r?\n/;
const clean = s => s.replace(ANSI_RE, '').trimEnd();
// main sentinel 수신 후 aux sentinel 을 기다리는 최대 시간 (aux 줄이 명령의 입력으로 소비된 경우 대비)
const AUX_GRACE_MS = 2000;

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

let seq = 0;

class Shell {
  constructor(stream) {
    this.stream = stream;
    this.buf = '';
    this.waiters = [];
    this.closed = false;
    this.queue = Promise.resolve(); // 같은 세션의 명령을 순차 실행한다 (공유 버퍼 보호)
    // 문자열로 받아 chunk 경계에서 멀티바이트 문자가 깨지지 않게 한다
    stream.setEncoding('utf8');
    stream.stderr?.setEncoding('utf8');
    stream.on('data', c => this._append(c));
    stream.stderr?.on('data', c => this._append(c));
    stream.on('error', () => {}); // 뒤따르는 close 에서 정리한다
    stream.once('close', () => {
      this.closed = true;
      this.waiters.splice(0).forEach(w => { clearTimeout(w.timer); w.resolve('close'); });
    });
  }

  _append(c) {
    this.buf += c;
    for (let i = this.waiters.length - 1; i >= 0; i--) {
      const w = this.waiters[i];
      if (!w.test(this.buf)) continue;
      clearTimeout(w.timer);
      this.waiters.splice(i, 1);
      w.resolve('match');
    }
  }

  // test(buf) 가 참이 되거나, timeoutMs 가 지나거나, 스트림이 닫힐 때까지 대기한다. 반환: 'match' | 'timeout' | 'close'
  _wait(test, timeoutMs) {
    return new Promise(resolve => {
      if (this.closed) return resolve('close');
      const w = { test, resolve };
      w.timer = setTimeout(() => {
        this.waiters.splice(this.waiters.indexOf(w), 1);
        resolve('timeout');
      }, timeoutMs);
      this.waiters.push(w);
    });
  }

  waitFor(re, timeoutMs) { return this._wait(buf => re.test(buf), timeoutMs); }

  send(text) {
    if (this.closed) throw new Error('shell closed');
    this.stream.write(text + '\n');
  }

  interrupt() { if (!this.closed) this.stream.write('\x03'); }

  // 큐에 넣어 순차 실행한다. 앞 작업의 실패는 뒤 작업에 전파하지 않는다
  enqueue(fn) {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => {});
    return run;
  }

  // 고유 sentinel 을 만든다. 따옴표로 분할해 보내므로 tty echo 줄(echoMark)에는 marker 리터럴이 나타나지 않는다
  _mark() {
    const id = `${Date.now()}_${++seq}`;
    return { marker: `${MARKER}_${id}`, echoMark: `echo ${MARKER}"_"${id}` };
  }

  // markers 중 하나가 수신될 때까지 대기한다. 이미 검사한 구간은 다시 보지 않는다
  _waitMarks(markers, timeoutMs) {
    const len = Math.max(...markers.map(m => m.length));
    let from = 0;
    return this._wait(buf => {
      const hit = markers.some(m => buf.indexOf(m, from) !== -1);
      from = Math.max(0, buf.length - len);
      return hit;
    }, timeoutMs);
  }

  // 버퍼를 비우고 markers 중 앞선 순서로 처음 발견된 marker 이전까지를 반환한다
  _take(...markers) {
    const out = this.buf;
    this.buf = '';
    const end = markers.map(m => out.indexOf(m)).find(i => i !== -1);
    return end === undefined ? out : out.slice(0, end);
  }

  // 명령 출력만 반환한다. 명령 줄 끝에 main sentinel 을, 별도 줄에 aux sentinel 을 보낸다.
  // csh 는 변수 미정의·glob 불일치 오류 시 줄 전체를 중단해 main 이 실행되지 않으므로 aux 로 종료를 감지한다.
  // 명령이 표준입력을 읽으면 aux 줄이 그 입력으로 소비될 수 있다. 타임아웃 시 Ctrl-C 로 명령을 중단한다
  async exec(command, timeoutMs = 30000) {
    const main = this._mark();
    const aux = this._mark();
    this.buf = '';
    const done = this._waitMarks([main.marker, aux.marker], timeoutMs);
    this.send(`${command} ; ${main.echoMark}\n${aux.echoMark}`);
    const result = await done;
    if (result === 'timeout') this.interrupt();
    // main 이 먼저 오면 aux 처리까지 기다려 다음 명령의 출력에 섞이지 않게 한다
    else if (result === 'match' && !this.buf.includes(aux.marker)) await this._waitMarks([aux.marker], AUX_GRACE_MS);
    const out = this._take(main.marker, aux.marker);
    // 마지막 명령 echo 줄까지와 그 앞의 잔여 출력(프롬프트 등)을 버린다. typeahead 로 들어간 줄은 echo 가 두 번 나타날 수 있다
    const e = out.lastIndexOf(main.echoMark);
    const nl = e === -1 ? -1 : out.indexOf('\n', e);
    const body = e === -1 ? out : nl === -1 ? '' : out.slice(nl + 1);
    const output = body.split('\n').filter(l => !l.includes(aux.echoMark)).join('\n');
    return { output: clean(output), timedOut: result === 'timeout' };
  }

  // 앞서 보낸 입력의 처리가 끝날 때까지 대기하고 그 출력을 반환한다 (echo 줄만 제거).
  // viewScript 처럼 새 셸을 띄우는 명령 뒤에서도 sentinel 은 typeahead 로 새 셸이 읽는다
  async sync(timeoutMs) {
    const m = this._mark();
    const done = this._waitMarks([m.marker], timeoutMs);
    this.send(m.echoMark);
    const result = await done;
    if (result === 'timeout') this.interrupt();
    const out = this._take(m.marker);
    if (result === 'timeout') throw new Error(`shell not responding after ${timeoutMs}ms:\n${clean(out)}`);
    return clean(out.split('\n').filter(l => !l.includes(m.echoMark)).join('\n'));
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
// 접속 진행 중인 세션: id → Promise<entry>. 동시 호출이 같은 접속을 기다리게 해 중복 연결을 막는다
const pending = new Map();

async function openConnection(meta) {
  const { host, port, username, password, privateKey } = meta;
  const conn = new Client();
  await new Promise((res, rej) => {
    // 호스트 키는 ~/.ssh-mcp/known_hosts 로 검증한다. 최초 접속 시 기록, 이후 불일치는 거부
    let mismatch = false;
    const opts = {
      host, port, username, algorithms: LEGACY,
      hostHash: 'sha256',
      hostVerifier: (fingerprint) => {
        mismatch = verifyHostKey(host, port, fingerprint) === 'mismatch';
        return !mismatch;
      },
      // 끊긴 연결(half-open)을 30초 안에 감지해 close 를 발생시킨다
      keepaliveInterval: 10000,
      keepaliveCountMax: 3,
    };
    if (password) opts.password = password;
    if (privateKey) opts.privateKey = privateKey;
    // error 는 ready 이후에도 발생할 수 있으므로 on 으로 받는다 (리스너가 없으면 프로세스가 종료된다)
    conn.once('ready', res).on('error', e => rej(mismatch
      ? new Error(`host key mismatch for ${host}:${port}; if the server key was legitimately changed, remove its line from ${KNOWN_HOSTS_PATH}`)
      : e));
    conn.connect(opts);
  });
  try {
    const stream = await new Promise((res, rej) =>
      conn.shell({ term: 'vt100', cols: 220, rows: 50 }, (e, s) => e ? rej(e) : res(s))
    );
    const shell = new Shell(stream);
    await shell.sync(15000); // 로그인 배너와 셸 초기화가 끝날 때까지 대기
    return { conn, shell };
  } catch (e) {
    conn.end();
    throw e;
  }
}

// viewScript(cleartool setview 래퍼)를 실행한다. 새 셸이 sentinel 을 처리하면 완료로 본다
async function runView(shell, viewScript) {
  shell.buf = '';
  shell.send(viewScript);
  return shell.sync(20000);
}

// rel 은 메뉴 출력 후 $< 로 프로젝트명을 읽는다. 메뉴 마지막 블록까지 받은 뒤 입력하고 XN_HOME 으로 결과를 확인한다
async function selectProject(shell, project) {
  shell.buf = '';
  const prompt = shell.waitFor(REL_PROMPT, 15000);
  shell.send('rel');
  if (await prompt !== 'match') {
    const out = clean(shell.buf);
    shell.interrupt();
    throw new Error(`rel prompt not detected:\n${out}`);
  }
  shell.buf = '';
  shell.send(project);
  const output = await shell.sync(15000);
  const { output: env } = await shell.exec('env | grep XN_HOME', 15000);
  const xnHome = env.match(/^XN_HOME=(\S+)/m)?.[1];
  return { output, env, selected: xnHome != null && path.posix.basename(xnHome) === project };
}

async function restoreState(shell, meta) {
  if (!meta.viewScript) return;
  if (meta.yuviewDone) await runView(shell, meta.viewScript);
  if (meta.project) await selectProject(shell, meta.project);
}

// 활성 세션으로 등록한다. 셸이나 연결이 닫히면 제거해 다음 호출에서 재접속하게 한다
function register(id, conn, shell, meta) {
  const entry = { conn, shell, meta };
  active.set(id, entry);
  const drop = () => { if (active.get(id) === entry) active.delete(id); };
  conn.once('close', drop);
  conn.on('error', drop);
  shell.stream.once('close', () => { drop(); conn.end(); });
  return entry;
}

// 접속 후 init(shell) 까지 마친 뒤 등록한다. init 실패 시 연결을 닫는다
async function open(id, meta, init) {
  const { conn, shell } = await openConnection(meta);
  try {
    await init(shell);
  } catch (e) {
    conn.end();
    throw e;
  }
  return register(id, conn, shell, meta);
}

function track(id, job) {
  const p = job.finally(() => pending.delete(id));
  pending.set(id, p);
  return p;
}

// host/username/viewScript 가 같은 저장 세션이 있으면 그 id 를 반환한다 (스토어 증식 방지)
function findStored({ host, username, viewScript }) {
  const hit = Object.entries(store.all()).find(([, m]) =>
    m.host === host && m.username === username && (m.viewScript || null) === viewScript);
  return hit ? hit[0] : null;
}

export async function ensure(id) {
  if (active.has(id)) return active.get(id);
  if (pending.has(id)) return pending.get(id);

  const meta = store.get(id);
  if (!meta) throw new Error(`session not found: ${id}`);
  return track(id, open(id, meta, shell => restoreState(shell, meta)));
}

export async function createSession(opts) {
  const viewScript = opts.viewScript || null;
  const id = findStored({ host: opts.host, username: opts.username, viewScript }) ?? randomUUID();
  if (pending.has(id)) await pending.get(id).catch(() => {});
  if (active.has(id)) return { id, output: '', reused: true };

  const meta = {
    host: opts.host,
    port: opts.port ?? 22,
    username: opts.username,
    password: opts.password ?? null,
    privateKey: opts.privateKey ?? null,
    viewScript,
    yuviewDone: false,
    project: null,
  };
  let output = '';
  await track(id, open(id, meta, async shell => {
    if (!viewScript) return;
    output = await runView(shell, viewScript);
    meta.yuviewDone = true;
  }));
  await store.upsert(id, meta); // 접속 성공 후 저장한다 (실패 시 고아 레코드 방지)
  return { id, output };
}

// ClearCase 명령(rel, ctco)은 viewScript 가 설정된 세션에서만 허용한다
export function requireView(id) {
  const meta = store.get(id);
  if (!meta) throw new Error(`session not found: ${id}`);
  if (!meta.viewScript) throw new Error(`session ${id} has no viewScript; ClearCase commands are not available`);
}

// 반환: { output, env, selected }
export async function setProject(id, project) {
  requireView(id);
  const { shell, meta } = await ensure(id);
  return shell.enqueue(async () => {
    const result = await selectProject(shell, project);
    if (result.selected) {
      meta.project = project;
      await store.upsert(id, { project });
    }
    return result;
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
