import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, readFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const {
  WATCHTOWER_CRON_MARKER,
  WATCHTOWER_LAUNCH_AGENT_LABEL,
  buildWatchtowerCronEntry,
  buildWatchtowerLaunchAgentPlist,
  getWatchtowerLaunchAgentPath,
  getWatchtowerLaunchAgentSourcePath,
  hasWatchtowerCronJob,
  installWatchtowerCronJob,
  installWatchtowerLaunchAgent,
  installWatchtowerSchedule,
  mergeCrontabContents,
} = require('../dist/cli/scheduler.js');

test('buildWatchtowerCronEntry builds a daily monitor cron entry with marker', () => {
  const entry = buildWatchtowerCronEntry({
    cliScriptPath: '/opt/reins/dist/cli/index.js',
    homeDir: '/Users/tester',
    nodePath: '/usr/local/bin/node',
    openclawHome: '/Users/tester/.openclaw',
  });

  assert.match(entry, /^0 9 \* \* \* /);
  assert.match(entry, /scan --monitor/);
  assert.match(entry, /scan-monitor\.log/);
  assert.match(entry, new RegExp(WATCHTOWER_CRON_MARKER.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('mergeCrontabContents replaces the existing reins watchtower line', () => {
  const current = [
    'MAILTO=""',
    '0 8 * * * /usr/bin/true # some-other-job',
    `0 9 * * * /usr/bin/node /old/index.js scan --monitor >> /tmp/log 2>&1 ${WATCHTOWER_CRON_MARKER}`,
    '',
  ].join('\n');
  const nextEntry = '0 9 * * * /usr/bin/node /new/index.js scan --monitor >> /tmp/new.log 2>&1 # reins-watchtower-scan';
  const merged = mergeCrontabContents(current, nextEntry);

  assert.equal(hasWatchtowerCronJob(merged), true);
  assert.match(merged, /MAILTO=""/);
  assert.match(merged, /some-other-job/);
  assert.match(merged, /\/new\/index\.js/);
  assert.doesNotMatch(merged, /\/old\/index\.js/);
});

test('buildWatchtowerLaunchAgentPlist builds a user LaunchAgent for daily scans', () => {
  const plist = buildWatchtowerLaunchAgentPlist({
    cliScriptPath: '/opt/reins/dist/cli/index.js',
    homeDir: '/Users/tester',
    nodePath: '/usr/local/bin/node',
    openclawHome: '/Users/tester/.openclaw',
  });

  assert.match(plist, new RegExp(WATCHTOWER_LAUNCH_AGENT_LABEL.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(plist, /<key>ProgramArguments<\/key>/);
  assert.match(plist, /<string>scan<\/string>/);
  assert.match(plist, /<string>--monitor<\/string>/);
  assert.match(plist, /<key>StartCalendarInterval<\/key>/);
  assert.match(plist, /<integer>9<\/integer>/);
});

test('installWatchtowerCronJob reads and writes crontab content via injected spawnSync', async () => {
  const tempRoot = mkdtempSync(path.join(os.tmpdir(), 'reins-scheduler-'));
  const openclawHome = path.join(tempRoot, '.openclaw');
  const calls = [];
  const fakeSpawnSync = (command, args, options = {}) => {
    calls.push({ args, command, options });

    if (command !== 'crontab') {
      throw new Error(`unexpected command ${command}`);
    }

    if (args[0] === '-l') {
      return {
        status: 0,
        stdout: 'MAILTO=""\n',
        stderr: '',
      };
    }

    if (args[0] === '-') {
      return {
        status: 0,
        stdout: '',
        stderr: '',
      };
    }

    throw new Error(`unexpected args ${args.join(' ')}`);
  };

  const result = await installWatchtowerCronJob({
    cliScriptPath: '/opt/reins/dist/cli/index.js',
    homeDir: tempRoot,
    nodePath: '/usr/local/bin/node',
    openclawHome,
    spawnSyncImpl: fakeSpawnSync,
  });

  assert.equal(result.alreadyInstalled, false);
  assert.equal(result.kind, 'cron');
  assert.equal(calls.length, 2);
  assert.equal(calls[0].args[0], '-l');
  assert.equal(calls[1].args[0], '-');
  assert.match(calls[1].options.input, /scan --monitor/);
  assert.match(calls[1].options.input, /# reins-watchtower-scan/);
});

test('installWatchtowerLaunchAgent writes plist and loads it with launchctl', async () => {
  const tempRoot = mkdtempSync(path.join(os.tmpdir(), 'reins-launchagent-'));
  const openclawHome = path.join(tempRoot, '.openclaw');
  const calls = [];
  const fakeSpawnSync = (command, args) => {
    calls.push({ args, command });

    if (command !== 'launchctl') {
      throw new Error(`unexpected command ${command}`);
    }

    if (args[0] === 'bootout') {
      return {
        status: 0,
        stdout: '',
        stderr: '',
      };
    }

    if (args[0] === 'bootstrap' || args[0] === 'kickstart') {
      return {
        status: 0,
        stdout: '',
        stderr: '',
      };
    }

    throw new Error(`unexpected args ${args.join(' ')}`);
  };

  const result = await installWatchtowerLaunchAgent({
    cliScriptPath: '/opt/reins/dist/cli/index.js',
    homeDir: tempRoot,
    nodePath: '/usr/local/bin/node',
    openclawHome,
    spawnSyncImpl: fakeSpawnSync,
    uid: 501,
  });

  const plistPath = getWatchtowerLaunchAgentPath({
    homeDir: tempRoot,
  });
  const sourcePlistPath = getWatchtowerLaunchAgentSourcePath({
    openclawHome,
  });
  const plistContents = readFileSync(plistPath, 'utf8');
  const sourcePlistContents = readFileSync(sourcePlistPath, 'utf8');

  assert.equal(result.alreadyInstalled, false);
  assert.equal(result.kind, 'launchagent');
  assert.equal(result.descriptor, sourcePlistPath);
  assert.match(plistContents, /scan-monitor\.log/);
  assert.equal(sourcePlistContents, plistContents);
  assert.equal(calls.length, 3);
  assert.deepEqual(calls[0].args, ['bootout', `gui/501/${WATCHTOWER_LAUNCH_AGENT_LABEL}`]);
  assert.deepEqual(calls[1].args, ['bootstrap', 'gui/501', plistPath]);
  assert.deepEqual(calls[2].args, ['kickstart', '-k', `gui/501/${WATCHTOWER_LAUNCH_AGENT_LABEL}`]);
});

test('installWatchtowerSchedule chooses LaunchAgent on macOS', async () => {
  const tempRoot = mkdtempSync(path.join(os.tmpdir(), 'reins-schedule-mac-'));
  const calls = [];
  const fakeSpawnSync = (command, args) => {
    calls.push({ args, command });
    return {
      status: 0,
      stdout: '',
      stderr: '',
    };
  };

  const result = await installWatchtowerSchedule({
    homeDir: tempRoot,
    openclawHome: path.join(tempRoot, '.openclaw'),
    platform: 'darwin',
    spawnSyncImpl: fakeSpawnSync,
    uid: 501,
  });

  assert.equal(result.kind, 'launchagent');
  assert.equal(calls[0].command, 'launchctl');
});
