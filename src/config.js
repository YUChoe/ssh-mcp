import fs from 'fs/promises';
import { encrypt, decrypt, isEncrypted } from './secret.js';
import { CONFIG_PATH, ensureHome } from './paths.js';

const DEFAULTS = {
  host: null,
  port: 22,
  username: null,
  password: null,
  viewScript: null,
  project: null,
};

let cfg = { ...DEFAULTS };

async function persist() {
  const out = { ...cfg, password: encrypt(cfg.password) };
  ensureHome();
  await fs.writeFile(CONFIG_PATH, JSON.stringify(out, null, 2), { encoding: 'utf8', mode: 0o600 });
}

export async function load() {
  try {
    const raw = JSON.parse(await fs.readFile(CONFIG_PATH, 'utf8'));
    const hasPlain = raw.password != null && !isEncrypted(raw.password);
    cfg = { ...DEFAULTS, ...raw, password: decrypt(raw.password) };
    if (hasPlain) await persist(); // 기존 평문 → 암호문 마이그레이션
  } catch {
    cfg = { ...DEFAULTS };
  }
}

export const get = () => ({ ...cfg });

export async function save(patch) {
  cfg = { ...cfg, ...patch };
  await persist();
  return { ...cfg };
}

export function validate() {
  const missing = ['host', 'username', 'password', 'viewScript', 'project']
    .filter(k => !cfg[k]);
  return missing.length === 0 ? null : missing;
}
