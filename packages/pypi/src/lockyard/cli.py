# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
"""Entry point that replaces itself with the packaged Lockyard binary."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


def binary_path() -> Path:
    name = "lockyard.exe" if os.name == "nt" else "lockyard"
    return Path(__file__).parent / "bin" / name


def main() -> int:
    binary = binary_path()
    if not binary.is_file():
        print(f"Lockyard binary is missing: {binary}", file=sys.stderr)
        return 1
    arguments = [str(binary), *sys.argv[1:]]
    if os.name == "nt":
        return subprocess.run(arguments, check=False).returncode
    os.execv(str(binary), arguments)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
