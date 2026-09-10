import fs from 'fs';
import os from 'os';
import path from 'path';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

// 키 파일은 프로젝트 외부(홈 디렉토리)에 두어 저장 파일과 분리한다
const KEY_PATH = path.join(os.homedir(), '.ssh-mcp', 'store.key');
const PREFIX = 'enc:v1:';

let key = null;

function loadKey() {
  if (key) return key;
  try {
    key = Buffer.from(fs.readFileSync(KEY_PATH, 'utf8').trim(), 'hex');
  } catch {
    key = randomBytes(32);
    fs.mkdirSync(path.dirname(KEY_PATH), { recursive: true });
    fs.writeFileSync(KEY_PATH, key.toString('hex'), { encoding: 'utf8', mode: 0o600 });
  }
  return key;
}

export const isEncrypted = (v) => typeof v === 'string' && v.startsWith(PREFIX);

export function encrypt(plain) {
  if (plain == null || isEncrypted(plain)) return plain;
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', loadKey(), iv);
  const ct = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  return PREFIX + [iv, cipher.getAuthTag(), ct].map(b => b.toString('base64')).join(':');
}

// 암호문이 아니면(기존 평문) 그대로 반환하여 마이그레이션을 허용한다
export function decrypt(value) {
  if (!isEncrypted(value)) return value;
  const [iv, tag, ct] = value.slice(PREFIX.length).split(':').map(s => Buffer.from(s, 'base64'));
  const decipher = createDecipheriv('aes-256-gcm', loadKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

// 객체의 지정 필드만 변환한 복사본을 반환한다
export const mapFields = (obj, fields, fn) =>
  Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, fields.includes(k) ? fn(v) : v]));
