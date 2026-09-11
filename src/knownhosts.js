import fs from 'fs';
import { KNOWN_HOSTS_PATH, ensureHome } from './paths.js';

// 형식: 한 줄에 "host:port <sha256 hex>". 최초 접속 시 기록하고(trust on first use) 이후 불일치는 거부한다
function load() {
  try {
    return new Map(
      fs.readFileSync(KNOWN_HOSTS_PATH, 'utf8').split('\n')
        .map(l => l.trim()).filter(Boolean)
        .map(l => l.split(/\s+/)).map(([k, v]) => [k, v])
    );
  } catch {
    return new Map();
  }
}

// 반환: 'ok' | 'added' | 'mismatch'
export function verifyHostKey(host, port, fingerprint) {
  const key = `${host}:${port}`;
  const known = load().get(key);
  if (known === undefined) {
    ensureHome();
    fs.appendFileSync(KNOWN_HOSTS_PATH, `${key} ${fingerprint}\n`, { encoding: 'utf8', mode: 0o600 });
    return 'added';
  }
  return known === fingerprint ? 'ok' : 'mismatch';
}
