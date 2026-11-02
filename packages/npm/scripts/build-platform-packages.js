#!/usr/bin/env node
// Copyright 2026 The Lockyard Authors.

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const targets = ['darwin-arm64', 'darwin-x64', 'linux-x64', 'linux-arm64', 'win32-x64'];
const source = process.argv[2];
if (!source) {
  process.stderr.write('usage: node scripts/build-platform-packages.js <built-binaries-folder>\n');
  process.exit(2);
}
const root = path.resolve(__dirname, '..');
const manifest = require(path.join(root, 'package.json'));
const { version } = manifest;
const dist = path.join(root, 'dist');
fs.rmSync(dist, { recursive: true, force: true });
fs.mkdirSync(dist, { recursive: true });
for (const target of targets) {
  const [platform, arch] = target.split('-');
  const executable = platform === 'win32' ? 'lockyard.exe' : 'lockyard';
  const candidates = [
    path.join(source, target, executable),
    path.join(source, `binary-${target}`, executable),
    path.join(source, `lockyard-${target}${platform === 'win32' ? '.exe' : ''}`),
  ];
  const input = candidates.find(candidate => fs.existsSync(candidate));
  if (!input) throw new Error(`Missing built binary for ${target}; looked for ${candidates.join(' and ')}`);
  const name = `lockyard-${target}`;
  const folder = path.join(dist, name);
  fs.mkdirSync(path.join(folder, 'bin'), { recursive: true });
  fs.copyFileSync(input, path.join(folder, 'bin', executable));
  if (platform !== 'win32') fs.chmodSync(path.join(folder, 'bin', executable), 0o755);
  fs.copyFileSync(path.join(root, 'LICENSE'), path.join(folder, 'LICENSE'));
  fs.writeFileSync(path.join(folder, 'package.json'), JSON.stringify({
    name, version, description: 'Lockyard native binary', license: 'Apache-2.0',
    homepage: 'https://lockyard.dev', repository: manifest.repository,
    os: [platform], cpu: [arch], files: ['bin', 'LICENSE'],
  }, null, 2) + '\n');
}
