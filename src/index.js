#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import * as session from './session.js';
import * as sftp from './sftp.js';
import * as store from './store.js';
import * as config from './config.js';

await store.load();
await config.load();

const server = new McpServer({ name: 'ssh-mcp', version: '0.2.0' });

// ── 설정 관리 ──────────────────────────────────────────────────────

server.tool(
  'get_config',
  '저장된 기본 연결 설정(host, username, viewScript, project 등)을 조회한다. 비밀번호는 마스킹된다',
  {},
  async () => {
    const cfg = config.get();
    const safe = { ...cfg, password: cfg.password ? '****' : null };
    return { content: [{ type: 'text', text: JSON.stringify(safe, null, 2) }] };
  }
);

server.tool(
  'save_config',
  '기본 연결 설정을 저장한다. 이후 connect() 호출 시 저장된 값이 사용된다',
  {
    host: z.string().describe('SSH 호스트 주소'),
    port: z.number().optional().describe('SSH 포트 (기본 22)'),
    username: z.string().describe('SSH 계정'),
    password: z.string().describe('SSH 패스워드'),
    viewScript: z.string().describe('ClearCase view 설정 스크립트명 (예: yuview)'),
    project: z.string().describe('기본 프로젝트명 (예: NEMS_LGU_V1.1)'),
  },
  async (args) => {
    const saved = await config.save(args);
    const safe = { ...saved, password: '****' };
    return { content: [{ type: 'text', text: JSON.stringify(safe, null, 2) }] };
  }
);

// ── 세션 연결 ──────────────────────────────────────────────────────

server.tool(
  'connect',
  '저장된 설정으로 SSH 연결 → viewScript 실행 → 프로젝트 설정까지 수행한다. 설정이 없으면 save_config를 먼저 호출해야 한다',
  {},
  async () => {
    const missing = config.validate();
    if (missing) {
      return {
        content: [{
          type: 'text',
          text: `설정 누락: ${missing.join(', ')}\nsave_config를 먼저 호출하세요`,
        }],
      };
    }

    const cfg = config.get();
    const { id, output } = await session.createSession(cfg);
    const { output: projOut, env } = await session.setProject(id, cfg.project);

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({ sessionId: id, viewOutput: output, projectOutput: projOut, env }),
      }],
    };
  }
);

server.tool(
  'create_session',
  '파라미터를 직접 지정해 SSH 연결 + viewScript 실행을 수행한다. 저장된 설정과 무관하게 동작한다',
  {
    host: z.string(),
    port: z.number().optional(),
    username: z.string(),
    password: z.string().optional(),
    privateKey: z.string().optional(),
    viewScript: z.string().describe('ClearCase view 설정 스크립트명'),
  },
  async (args) => {
    const result = await session.createSession(args);
    return { content: [{ type: 'text', text: JSON.stringify(result) }] };
  }
);

server.tool(
  'set_project',
  'rel 실행 후 프로젝트를 선택해 XN_HOME 환경을 설정한다',
  {
    sessionId: z.string(),
    project: z.string().describe('프로젝트명 예) NEMS_LGU_V1.1'),
  },
  async ({ sessionId, project }) => {
    const result = await session.setProject(sessionId, project);
    return { content: [{ type: 'text', text: JSON.stringify(result) }] };
  }
);

// ── 명령 실행 ──────────────────────────────────────────────────────

server.tool(
  'exec',
  'VOB 환경에서 쉘 명령(ls, grep, find, ctls 등)을 실행하고 출력을 반환한다',
  {
    sessionId: z.string(),
    command: z.string(),
    timeoutMs: z.number().optional(),
  },
  async ({ sessionId, command, timeoutMs }) => {
    const out = await session.execCommand(sessionId, command, timeoutMs);
    return { content: [{ type: 'text', text: out }] };
  }
);

server.tool(
  'send_input',
  '인터랙티브 프롬프트에 텍스트를 입력하고 다음 출력을 반환한다',
  {
    sessionId: z.string(),
    input: z.string(),
    quietMs: z.number().optional(),
    timeoutMs: z.number().optional(),
  },
  async ({ sessionId, input, quietMs, timeoutMs }) => {
    const out = await session.sendInput(sessionId, input, quietMs, timeoutMs);
    return { content: [{ type: 'text', text: out }] };
  }
);

// ── 파일 교환 ──────────────────────────────────────────────────────

server.tool(
  'download_file',
  '서버에서 로컬로 파일을 내려받는다. 원격 경로 구조를 유지하며 MD5 체크섬을 반환한다',
  {
    sessionId: z.string(),
    remotePath: z.string().describe('서버의 절대 경로'),
    localBase: z.string().optional().describe('로컬 저장 기준 디렉토리 (기본: ./downloads)'),
  },
  async ({ sessionId, remotePath, localBase }) => {
    const result = await sftp.downloadFile(sessionId, remotePath, localBase);
    return { content: [{ type: 'text', text: JSON.stringify(result) }] };
  }
);

server.tool(
  'upload_file',
  '로컬 파일을 서버로 업로드하고 MD5 체크섬으로 정합성을 검증한다',
  {
    sessionId: z.string(),
    localPath: z.string(),
    remotePath: z.string(),
  },
  async ({ sessionId, localPath, remotePath }) => {
    const result = await sftp.uploadFile(sessionId, localPath, remotePath);
    return { content: [{ type: 'text', text: JSON.stringify(result) }] };
  }
);

// ── ClearCase ──────────────────────────────────────────────────────

server.tool(
  'checkout',
  '클리어케이스 ctco로 파일을 체크아웃한다',
  {
    sessionId: z.string(),
    remotePath: z.string(),
    comment: z.string().optional(),
  },
  async ({ sessionId, remotePath, comment }) => {
    const commentArg = comment ? `-c "${comment}"` : '-nc';
    const out = await session.execCommand(sessionId, `ctco ${commentArg} ${remotePath}`);
    return { content: [{ type: 'text', text: out }] };
  }
);

// ── 세션 관리 ──────────────────────────────────────────────────────

server.tool(
  'list_sessions',
  '저장된 모든 세션과 현재 연결 상태를 반환한다',
  {},
  async () => {
    const list = session.listSessions();
    return { content: [{ type: 'text', text: JSON.stringify(list, null, 2) }] };
  }
);

server.tool(
  'close_session',
  '세션을 종료하고 스토어에서 제거한다',
  { sessionId: z.string() },
  async ({ sessionId }) => {
    await session.closeSession(sessionId);
    return { content: [{ type: 'text', text: 'closed' }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
