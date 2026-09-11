import fs from 'fs';
import os from 'os';
import path from 'path';

// 설정/세션/키 파일은 소스와 분리해 사용자 홈 디렉토리에 둔다 (npx 캐시 디렉토리는 휘발성)
export const HOME_DIR = path.join(os.homedir(), '.ssh-mcp');
export const KEY_PATH = path.join(HOME_DIR, 'store.key');
export const CONFIG_PATH = path.join(HOME_DIR, 'connection-config.json');
export const STORE_PATH = path.join(HOME_DIR, 'session-store.json');

// 디렉토리는 소유자 전용(0700)으로 생성한다. Windows 는 mode 를 무시하고 %USERPROFILE% ACL 을 상속한다
export function ensureHome() {
  fs.mkdirSync(HOME_DIR, { recursive: true, mode: 0o700 });
}
