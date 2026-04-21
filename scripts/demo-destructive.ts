import fs from 'fs';
import os from 'os';
import path from 'path';

process.env.REINS_DESTRUCTIVE_GATING = 'on';
process.env.REINS_BULK_THRESHOLD = '20';
process.env.OPENCLAW_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'reins-demo-'));

async function run(): Promise<void> {
  const { Interceptor } = await import('../src/core/Interceptor');
  const { createToolCallHook } = await import('../src/plugin/tool-interceptor');

  const interceptor = new Interceptor({
    defaultAction: 'ALLOW',
    modules: {},
  });
  interceptor.respondToolAvailable = true;

  const hook = createToolCallHook(interceptor);
  const sessionKey = 'demo:destructive-intercept';

  console.log('\n=== Demo: Pre-Execution Destructive Intercept ===\n');

  const first = await hook(
    {
      toolName: 'Gmail.deleteMessages',
      params: { query: 'in:inbox', count: 4382 },
    },
    {
      toolName: 'Gmail.deleteMessages',
      sessionKey,
    }
  );

  console.log('1) Initial tool call blocked:');
  console.log(first);

  const token = String(first?.blockReason || '').match(/CONFIRM-[A-Z0-9]+/)?.[0];
  if (!token) {
    throw new Error('Expected confirmation token in blockReason but none was found.');
  }

  const yes = await hook(
    {
      toolName: 'reins.respond',
      params: { decision: 'yes' },
    },
    {
      toolName: 'reins.respond',
      sessionKey,
    }
  );

  console.log('\n2) YES is rejected for catastrophic action:');
  console.log(yes);

  const confirm = await hook(
    {
      toolName: 'reins.respond',
      params: { decision: 'confirm', confirmation: token },
    },
    {
      toolName: 'reins.respond',
      sessionKey,
    }
  );

  console.log('\n3) Explicit CONFIRM token accepted:');
  console.log(confirm);

  const retry = await hook(
    {
      toolName: 'Gmail.deleteMessages',
      params: { query: 'in:inbox', count: 4382 },
    },
    {
      toolName: 'Gmail.deleteMessages',
      sessionKey,
    }
  );

  console.log('\n4) Retry after confirmation now passes pre-exec gate:');
  console.log(retry);
}

run().catch((error) => {
  console.error('Demo failed:', error);
  process.exit(1);
});
