#!/usr/bin/env node
// Copyright 2026 The Lockyard Authors.

'use strict';

const { spawn } = require('node:child_process');

const packages = {
  'darwin-arm64': 'lockyard-darwin-arm64',
  'darwin-x64': 'lockyard-darwin-x64',
  'linux-x64': 'lockyard-linux-x64',
  'linux-arm64': 'lockyard-linux-arm64',
  'win32-x64': 'lockyard-win32-x64',
};

function binaryPath(platform = process.platform, arch = process.arch, resolve = require.resolve) {
  const packageName = packages[`${platform}-${arch}`];
  if (!packageName) throw new Error(`No Lockyard binary package is available for ${platform}-${arch}.`);
  let manifest;
  try {
    manifest = resolve(`${packageName}/package.json`);
  } catch {
    throw new Error(`Lockyard has no installed binary package for ${platform}-${arch}. Reinstall lockyard for this platform.`);
  }
  return require('node:path').join(require('node:path').dirname(manifest), 'bin', platform === 'win32' ? 'lockyard.exe' : 'lockyard');
}

function main(args = process.argv.slice(2)) {
  let executable;
  try {
    executable = binaryPath();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
    return;
  }
  const child = spawn(executable, args, { stdio: 'inherit', windowsHide: true });
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.on(signal, () => { if (!child.killed) child.kill(signal); });
  }
  child.on('error', error => {
    process.stderr.write(`Could not start Lockyard binary: ${error.message}\n`);
    process.exitCode = 1;
  });
  child.on('exit', (code, signal) => {
    if (signal) {
      process.removeAllListeners(signal);
      process.kill(process.pid, signal);
    }
    else process.exitCode = code === null ? 1 : code;
  });
}

if (require.main === module) main();
module.exports = { binaryPath, main };
