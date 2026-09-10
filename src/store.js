import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { encrypt, decrypt, isEncrypted, mapFields } from './secret.js';

const STORE_PATH = path.join(
  path.dirname(fileURLToPath(import.meta.url)), '..', 'session-store.json'
);

const SECRET_FIELDS = ['password', 'privateKey'];

let data = { sessions: {} };

export async function load() {
  let raw;
  try {
    raw = JSON.parse(await fs.readFile(STORE_PATH, 'utf8'));
  } catch {
    data = { sessions: {} };
    return;
  }
  const sessions = raw.sessions ?? {};
  // 기존 평문 값이 하나라도 있으면 복호화 후 즉시 암호문으로 재저장한다
  const hasPlain = Object.values(sessions)
    .some(m => SECRET_FIELDS.some(k => m[k] != null && !isEncrypted(m[k])));
  data = { sessions: Object.fromEntries(
    Object.entries(sessions).map(([id, m]) => [id, mapFields(m, SECRET_FIELDS, decrypt)])
  ) };
  if (hasPlain) await persist();
}

async function persist() {
  const out = { sessions: Object.fromEntries(
    Object.entries(data.sessions).map(([id, m]) => [id, mapFields(m, SECRET_FIELDS, encrypt)])
  ) };
  await fs.writeFile(STORE_PATH, JSON.stringify(out, null, 2), 'utf8');
}

export const get = (id) => data.sessions[id] ?? null;
export const all = () => ({ ...data.sessions });

export async function upsert(id, patch) {
  data.sessions[id] = { ...data.sessions[id], ...patch };
  await persist();
}

export async function remove(id) {
  delete data.sessions[id];
  await persist();
}
