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

// 전체 교체한다. 병합하면 ClearCase 서버에서 미사용 서버로 바꿀 때 이전 viewScript/project 가 남는다
export async function save(next) {
  cfg = { ...DEFAULTS, ...next };
  await persist();
  return { ...cfg };
}

// viewScript/project 는 ClearCase 서버에서만 지정한다. project 는 viewScript 가 있어야 의미가 있다
export function validate() {
  const missing = ['host', 'username', 'password'].filter(k => !cfg[k]);
  if (cfg.project && !cfg.viewScript) missing.push('viewScript');
  return missing.length === 0 ? null : missing;
}
