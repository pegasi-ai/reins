import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  exchangeCliAuthLogin,
  logoutCliAuth,
  refreshCliAuthSession,
  startCliAuthLogin,
  whoAmICliAuth,
} = require('../dist/lib/watchtower-client.js');

async function withServer(handler, run) {
  const server = http.createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  try {
    await run(baseUrl);
  } finally {
    server.close();
    await once(server, 'close');
  }
}

async function readJsonBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

test('CLI auth client implements start, exchange, refresh, whoami, and logout contracts', async () => {
  const seen = [];

  await withServer(async (req, res) => {
    if (!req.url) {
      res.writeHead(500).end();
      return;
    }

    const body = req.method === 'POST' ? await readJsonBody(req) : null;
    seen.push({
      authorization: req.headers.authorization,
      body,
      method: req.method,
      url: req.url,
    });

    if (req.method === 'POST' && req.url === '/api/cli/auth/start') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        login_id: 'login_123',
        status: 'pending',
        method: 'magic_link',
        email: 'user@example.com',
        expires_at: '2026-04-21T10:15:00Z',
        message: 'Magic link sent.',
      }));
      return;
    }

    if (req.method === 'POST' && req.url === '/api/cli/auth/exchange') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        login_id: 'login_123',
        status: 'complete',
        user: {
          id: 'user_123',
          name: 'Kevin Wu',
          email: 'user@example.com',
          role: 'dev',
        },
        access_token: 'cli_sess_access',
        refresh_token: 'cli_sess_refresh',
        access_token_expires_at: '2026-04-21T10:15:00Z',
        refresh_token_expires_at: '2026-05-21T10:00:00Z',
        dashboard_url: 'http://127.0.0.1/dashboard',
        api_key: 'cr_cli_api_key',
      }));
      return;
    }

    if (req.method === 'POST' && req.url === '/api/cli/auth/refresh') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        login_id: 'login_refresh',
        status: 'complete',
        user: {
          id: 'user_123',
          name: 'Kevin Wu',
          email: 'user@example.com',
          role: 'admin',
        },
        access_token: 'cli_sess_access_rotated',
        refresh_token: 'cli_sess_refresh_rotated',
        access_token_expires_at: '2026-04-21T10:30:00Z',
        refresh_token_expires_at: '2026-05-21T10:15:00Z',
        dashboard_url: 'http://127.0.0.1/dashboard',
      }));
      return;
    }

    if (req.method === 'GET' && req.url === '/api/cli/auth/whoami') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        user: {
          id: 'user_123',
          name: 'Kevin Wu',
          email: 'user@example.com',
          role: 'dev',
        },
      }));
      return;
    }

    if (req.method === 'POST' && req.url === '/api/cli/auth/logout') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    res.writeHead(404).end();
  }, async (baseUrl) => {
    const started = await startCliAuthLogin({
      method: 'magic_link',
      email: 'user@example.com',
    }, baseUrl);
    assert.equal(started.login_id, 'login_123');
    assert.equal(started.method, 'magic_link');
    assert.equal(started.email, 'user@example.com');

    const exchanged = await exchangeCliAuthLogin('login_123', baseUrl);
    assert.equal(exchanged.status, 'complete');
    assert.equal(exchanged.user.email, 'user@example.com');
    assert.equal(exchanged.access_token, 'cli_sess_access');
    assert.equal(exchanged.api_key, 'cr_cli_api_key');

    const refreshed = await refreshCliAuthSession('cli_sess_refresh', baseUrl);
    assert.equal(refreshed.access_token, 'cli_sess_access_rotated');
    assert.equal(refreshed.user.role, 'admin');
    assert.equal(refreshed.api_key, undefined);

    const whoami = await whoAmICliAuth('cli_sess_access_rotated', baseUrl);
    assert.equal(whoami.user.name, 'Kevin Wu');

    await logoutCliAuth('cli_sess_access_rotated', baseUrl, 'cli_sess_refresh_rotated');
  });

  assert.deepEqual(seen[0].body, {
    method: 'magic_link',
    email: 'user@example.com',
  });
  assert.deepEqual(seen[1].body, { login_id: 'login_123' });
  assert.deepEqual(seen[2].body, { refresh_token: 'cli_sess_refresh' });
  assert.equal(seen[3].authorization, 'Bearer cli_sess_access_rotated');
  assert.equal(seen[4].authorization, 'Bearer cli_sess_access_rotated');
  assert.deepEqual(seen[4].body, { refresh_token: 'cli_sess_refresh_rotated' });
});
