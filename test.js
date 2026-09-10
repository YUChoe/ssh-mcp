import { createSession, sendInput, execCommand, closeSession } from './src/session.js';
import * as config from './src/config.js';

// 자격증명은 connection-config.json 에서 읽는다 (save_config 로 저장)
await config.load();
const { host, port, username, password, viewScript } = config.get();
const opts = { host, port, username, password, viewScript };

// 1단계
const { id } = await createSession(opts);
console.log('=== 1단계: yuview ===');
await sendInput(id, 'yuview', 1000, 8000);
const env1 = await execCommand(id, 'env | grep CLEARCASE_CMDLINE');
console.log(env1);

// 2단계 - NEMS_LGU_V1.1
console.log('\n=== 2단계-a: rel 실행 ===');
const relOut1 = await sendInput(id, 'rel', 1500, 10000);
console.log(relOut1);

console.log('\n=== 2단계-b: NEMS_LGU_V1.1 선택 ===');
const selOut1 = await sendInput(id, 'NEMS_LGU_V1.1', 1500, 15000);
console.log(selOut1);

const xnHome1 = await execCommand(id, 'env | grep XN_HOME');
console.log('XN_HOME check:', xnHome1);
console.log(xnHome1.includes('XN_HOME=/vobs/SI/NEMS_LGU_V1.1') ? '✓ V1.1 확인' : '✗ 실패');

// 2단계 - NEMS_LGU_V1.0
console.log('\n=== 2단계-c: rel 재실행 ===');
const relOut2 = await sendInput(id, 'rel', 1500, 10000);
console.log(relOut2);

console.log('\n=== 2단계-d: NEMS_LGU_V1.0 선택 ===');
const selOut2 = await sendInput(id, 'NEMS_LGU_V1.0', 1500, 15000);
console.log(selOut2);

const xnHome2 = await execCommand(id, 'env | grep XN_HOME');
console.log('XN_HOME check:', xnHome2);
console.log(xnHome2.includes('XN_HOME=/vobs/SI/NEMS_LGU_V1.0') ? '✓ V1.0 확인 - 2단계 완료' : '✗ 실패');

closeSession(id);
