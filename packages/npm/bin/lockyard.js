#!/usr/bin/env node
// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

'use strict';

const { spawnSync } = require('node:child_process');

const PLATFORMS = {
  'darwin-arm64': 'lockyard-darwin-arm64',
  'darwin-x64': 'lockyard-darwin-x64',
  'linux-x64': 'lockyard-linux-x64',
  'linux-arm64': 'lockyard-linux-arm64',
  'win32-x64': 'lockyard-win32-x64',
};

/// Resolves the native executable installed by the optional platform package.
function binaryPath(platform = process.platform, arch = process.arch) {
  const name = PLATFORMS[`${platform}-${arch}`];
  if (!name) {
    throw new Error(
      `No Lockyard binary package is available for ${platform}-${arch}. ` +
        'Install with `cargo install lockyard` instead.'
    );
  }
  const executable = platform === 'win32' ? 'lockyard.exe' : 'lockyard';
  // The platform package ships only the binary, so resolve its manifest and walk to bin/.
  let manifest;
  try {
    manifest = require.resolve(`${name}/package.json`);
  } catch {
    // An install run with --no-optional, or one that failed partway, leaves the wrapper alone.
    throw new Error(
      `The Lockyard binary package ${name} is not installed. ` +
        'Reinstall with `npm install -g lockyard` (optional dependencies must be allowed).'
    );
  }
  return require('node:path').join(require('node:path').dirname(manifest), 'bin', executable);
}

function main() {
  let binary;
  try {
    binary = binaryPath();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    return 1;
  }
  // The child owns the terminal: Lockyard's MCP server speaks over stdio and hooks read stdin.
  const result = spawnSync(binary, process.argv.slice(2), { stdio: 'inherit' });
  if (result.error) {
    process.stderr.write(`Could not run ${binary}: ${result.error.message}\n`);
    return 1;
  }
  // A killed child has no exit code; report the usual shell encoding of a signal.
  if (result.status === null && result.signal) return 128;
  return result.status ?? 1;
}

module.exports = { binaryPath, PLATFORMS };

if (require.main === module) process.exit(main());
