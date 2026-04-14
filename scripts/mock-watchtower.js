#!/usr/bin/env node

const http = require('node:http');
const { mkdirSync, writeFileSync } = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

function parseArgs(argv) {
  const options = {
    host: '127.0.0.1',
    port: 8787,
    outputDir: path.join(os.tmpdir(), 'clawreins-watchtower-mock'),
  };

  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];

    if (value === '--help' || value === '-h') {
      options.help = true;
      continue;
    }

    if (value === '--host' && argv[index + 1]) {
      options.host = argv[index + 1];
      index += 1;
      continue;
    }

    if (value === '--port' && argv[index + 1]) {
      options.port = Number.parseInt(argv[index + 1], 10);
      index += 1;
      continue;
    }

    if (value === '--output-dir' && argv[index + 1]) {
      options.outputDir = path.resolve(argv[index + 1]);
      index += 1;
    }
  }

  return options;
}

function printHelp() {
  console.log('Mock Watchtower server for local ClawReins testing');
  console.log('');
  console.log('Usage:');
  console.log('  node scripts/mock-watchtower.js [--host 127.0.0.1] [--port 8787] [--output-dir /tmp/mock]');
  console.log('');
  console.log('Endpoints:');
  console.log('  POST /api/watchtower/connect');
  console.log('  POST /api/scan-artifacts/ingest');
  console.log('  GET  /dashboard/:id');
  console.log('  GET  /_mock/requests');
}

function json(response, statusCode, payload) {
  response.statusCode = statusCode;
  response.setHeader('content-type', 'application/json');
  response.end(JSON.stringify(payload, null, 2));
}

function text(response, statusCode, payload) {
  response.statusCode = statusCode;
  response.setHeader('content-type', 'text/plain; charset=utf-8');
  response.end(payload);
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];

    request.on('data', (chunk) => {
      chunks.push(chunk);
    });

    request.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8').trim();
        resolve(raw.length > 0 ? JSON.parse(raw) : {});
      } catch (error) {
        reject(error);
      }
    });

    request.on('error', reject);
  });
}

function safeSlug(value) {
  return String(value || 'repo')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'repo';
}

function nowStamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

const options = parseArgs(process.argv.slice(2));

if (options.help) {
  printHelp();
  process.exit(0);
}

if (!Number.isInteger(options.port) || options.port <= 0) {
  console.error('Invalid --port value');
  process.exit(1);
}

mkdirSync(options.outputDir, { recursive: true });

const connections = new Map();
const requests = [];
const apiKeys = new Map();

const server = http.createServer(async (request, response) => {
  const requestUrl = new URL(request.url || '/', `http://${request.headers.host || `${options.host}:${options.port}`}`);

  try {
    if (request.method === 'POST' && requestUrl.pathname === '/api/watchtower/connect') {
      const body = await readJson(request);
      const email = String(body.email || '').trim();

      if (!email || !email.includes('@')) {
        json(response, 400, { error: 'email is required' });
        return;
      }

      const repository = body.repository && typeof body.repository === 'object' ? body.repository : {};
      const displayName = String(repository.displayName || 'local-repo');
      const repositoryId = String(repository.id || displayName);
      const dashboardId = `${safeSlug(displayName)}-${crypto.randomBytes(3).toString('hex')}`;
      const apiKey = `wt_mock_${crypto.randomBytes(12).toString('hex')}`;
      const dashboardUrl = `http://${options.host}:${options.port}/dashboard/${dashboardId}`;

      connections.set(apiKey, {
        apiKey,
        connectedAt: new Date().toISOString(),
        dashboardId,
        dashboardUrl,
        email,
        repositoryId,
        displayName,
      });
      apiKeys.set(repositoryId, apiKey);

      const payload = {
        apiKey,
        dashboardUrl,
      };
      const filePath = path.join(options.outputDir, `${nowStamp()}-connect.json`);
      writeFileSync(filePath, JSON.stringify({ request: body, response: payload }, null, 2));

      requests.push({
        kind: 'connect',
        method: request.method,
        path: requestUrl.pathname,
        headers: request.headers,
        body,
        filePath,
        createdAt: new Date().toISOString(),
      });

      console.log(`[mock-watchtower] connected ${email} -> ${dashboardUrl}`);
      json(response, 200, payload);
      return;
    }

    if (request.method === 'POST' && requestUrl.pathname === '/api/scan-artifacts/ingest') {
      const apiKey = String(request.headers['x-api-key'] || '').trim();
      if (!apiKey || !connections.has(apiKey)) {
        json(response, 401, { error: 'invalid x-api-key' });
        return;
      }

      const body = await readJson(request);
      const filePath = path.join(options.outputDir, `${nowStamp()}-artifact.json`);
      writeFileSync(filePath, JSON.stringify(body, null, 2));

      requests.push({
        kind: 'artifact',
        method: request.method,
        path: requestUrl.pathname,
        headers: request.headers,
        body,
        filePath,
        createdAt: new Date().toISOString(),
      });

      console.log(`[mock-watchtower] artifact received -> ${filePath}`);
      json(response, 200, {
        ok: true,
        storedAt: filePath,
      });
      return;
    }

    if (request.method === 'GET' && requestUrl.pathname.startsWith('/dashboard/')) {
      const dashboardId = requestUrl.pathname.split('/').pop() || 'unknown';
      const connection = Array.from(connections.values()).find((entry) => entry.dashboardId === dashboardId);

      text(
        response,
        200,
        [
          'Mock Watchtower Dashboard',
          '',
          `dashboardId: ${dashboardId}`,
          `email: ${connection ? connection.email : 'unknown'}`,
          `repository: ${connection ? connection.displayName : 'unknown'}`,
          '',
          `Artifacts saved under: ${options.outputDir}`,
          'Recent requests: GET /_mock/requests',
        ].join('\n')
      );
      return;
    }

    if (request.method === 'GET' && requestUrl.pathname === '/_mock/requests') {
      json(response, 200, {
        outputDir: options.outputDir,
        requests,
      });
      return;
    }

    json(response, 404, { error: 'not found' });
  } catch (error) {
    json(response, 500, {
      error: error instanceof Error ? error.message : String(error),
    });
  }
});

server.listen(options.port, options.host, () => {
  console.log('Mock Watchtower server is running');
  console.log(`Base URL: http://${options.host}:${options.port}`);
  console.log(`Connect endpoint: http://${options.host}:${options.port}/api/watchtower/connect`);
  console.log(`Artifact endpoint: http://${options.host}:${options.port}/api/scan-artifacts/ingest`);
  console.log(`Dashboard example: http://${options.host}:${options.port}/dashboard/demo`);
  console.log(`Request log: http://${options.host}:${options.port}/_mock/requests`);
  console.log(`Artifacts directory: ${options.outputDir}`);
});

function shutdown(signal) {
  console.log(`\n[mock-watchtower] shutting down on ${signal}`);
  server.close(() => {
    process.exit(0);
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
