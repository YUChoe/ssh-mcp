import fs from 'fs/promises';
import { createHash } from 'crypto';
import path from 'path';
import * as session from './session.js';

function md5(buf) {
  return createHash('md5').update(buf).digest('hex');
}

function openSftp(conn) {
  return new Promise((res, rej) => conn.sftp((e, s) => e ? rej(e) : res(s)));
}

export async function downloadFile(sessionId, remotePath, localBase = './downloads') {
  const entry = await session.ensure(sessionId);
  const sft = await openSftp(entry.conn);

  // 원격 경로 구조를 localBase 아래에 재현한다. '..' 등으로 localBase 를 벗어나는 경로는 거부한다
  const base = path.resolve(localBase);
  const localPath = path.resolve(base, ...remotePath.split('/').filter(Boolean));
  if (!localPath.startsWith(base + path.sep)) {
    throw new Error(`remotePath escapes localBase: ${remotePath}`);
  }
  await fs.mkdir(path.dirname(localPath), { recursive: true });

  await new Promise((res, rej) =>
    sft.fastGet(remotePath, localPath, e => e ? rej(e) : res())
  );
  sft.end();

  const buf = await fs.readFile(localPath);
  return { localPath, remotePath, checksum: md5(buf), size: buf.length };
}

export async function uploadFile(sessionId, localPath, remotePath) {
  const entry = await session.ensure(sessionId);
  const buf = await fs.readFile(localPath);
  const localChecksum = md5(buf);

  const sft = await openSftp(entry.conn);

  // 원격 디렉토리 보장
  const remoteDir = remotePath.split('/').slice(0, -1).join('/');
  if (remoteDir) {
    await new Promise(res => sft.mkdir(remoteDir, () => res())); // 존재해도 무시
  }

  await new Promise((res, rej) =>
    sft.fastPut(localPath, remotePath, e => e ? rej(e) : res())
  );
  sft.end();

  // 원격 md5sum으로 체크섬 검증
  const { output } = await session.execCommand(sessionId, `md5sum ${session.shellQuote(remotePath)} | awk '{print $1}'`);
  const remoteChecksum = output.trim();

  return {
    localPath,
    remotePath,
    localChecksum,
    remoteChecksum,
    match: remoteChecksum === localChecksum,
  };
}
