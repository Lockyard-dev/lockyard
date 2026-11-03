// Copyright 2026 The Lockyard Authors.

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { binaryPath } = require('../bin/lockyard.js');

const launcher = path.resolve(__dirname, '../bin/lockyard.js');

// The fake binary is a shell script, so this runs where a shell does; Windows is covered by the release build.
test('launcher passes arguments, stdio and child exit code through', { skip: process.platform === 'win32' }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lockyard-npm-'));
  const name = `lockyard-${process.platform}-${process.arch}`;
  const pkg = path.join(dir, 'node_modules', name);
  fs.mkdirSync(path.join(pkg, 'bin'), { recursive: true });
  fs.writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({ name }));
  const binary = path.join(pkg, 'bin', 'lockyard');
  fs.writeFileSync(binary, '#!/bin/sh\nprintf "%s\\n" "$@"\nexit 7\n', { mode: 0o755 });
  const result = spawnSync(process.execPath, [launcher, 'zone', 'list'], {
    env: { ...process.env, NODE_PATH: path.join(dir, 'node_modules') }, encoding: 'utf8',
  });
  assert.equal(result.status, 7);
  assert.equal(result.stdout, 'zone\nlist\n');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('unsupported platform reports a clear error', () => {
  assert.throws(() => binaryPath('freebsd', 'x64'), /No Lockyard binary package is available for freebsd-x64/);
});
