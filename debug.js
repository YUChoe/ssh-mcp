import { Client } from 'ssh2';
import * as config from './src/config.js';

// 자격증명은 connection-config.json 에서 읽는다 (save_config 로 저장)
await config.load();
const { host, port, username, password } = config.get();
const conn = new Client();

const LEGACY = {
  kex: ['diffie-hellman-group14-sha1','diffie-hellman-group1-sha1','ecdh-sha2-nistp256'],
  cipher: ['aes128-ctr','aes192-ctr','aes256-ctr','aes128-cbc','3des-cbc'],
  serverHostKey: ['ssh-rsa','ssh-dss','ecdsa-sha2-nistp256'],
  hmac: ['hmac-sha2-256','hmac-sha1'],
};

await new Promise((resolve, reject) => {
  conn.once('ready', resolve).once('error', reject);
  conn.connect({ host, port, username, password, algorithms: LEGACY, hostVerifier:()=>true });
});

const stream = await new Promise((res, rej) =>
  conn.shell({ term:'xterm', cols:220, rows:50 }, (e, s) => e ? rej(e) : res(s))
);

// 모든 출력을 타임스탬프와 함께 출력
stream.on('data', (chunk) => {
  process.stdout.write(`[DATA] ${JSON.stringify(chunk.toString())}\n`);
});
stream.stderr?.on('data', (chunk) => {
  process.stdout.write(`[STDERR] ${JSON.stringify(chunk.toString())}\n`);
});

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const send = (cmd) => {
  console.log(`\n>>> SEND: ${JSON.stringify(cmd)}`);
  stream.write(cmd + '\n');
};

// 1. 초기 프롬프트 대기
await sleep(3000);
console.log('\n--- yuview 실행 ---');
send('yuview');

await sleep(5000);
console.log('\n--- env 실행 ---');
send('env | grep CLEARCASE');

await sleep(3000);
console.log('\n--- done ---');
stream.end();
conn.end();
