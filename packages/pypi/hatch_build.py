# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
"""Adds the release binary and target wheel tag to a platform wheel."""

from __future__ import annotations

import os
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    """Requires one target binary for each wheel build."""

    def initialize(self, version: str, build_data: dict[str, object]) -> None:
        source = os.environ.get("LOCKYARD_BINARY")
        tag = os.environ.get("LOCKYARD_PLATFORM_TAG")
        if not source or not Path(source).is_file():
            raise RuntimeError("LOCKYARD_BINARY must name the built Lockyard executable")
        if not tag:
            raise RuntimeError("LOCKYARD_PLATFORM_TAG must name the wheel platform tag")
        executable = "lockyard.exe" if Path(source).suffix.lower() == ".exe" else "lockyard"
        build_data["force_include"] = {source: f"lockyard/bin/{executable}"}
        build_data["tag"] = f"py3-none-{tag}"
