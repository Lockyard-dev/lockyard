# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
"""Tests the Python entry point with a fake native executable."""

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lockyard import cli


class CliTests(unittest.TestCase):
    def test_missing_binary_reports_a_clear_error(self):
        with patch.object(cli, "binary_path", return_value=Path("/no/such/lockyard")):
            with patch("sys.stderr") as stderr:
                self.assertEqual(cli.main(), 1)
                stderr.write.assert_called()

    @unittest.skipIf(os.name == "nt", "the Windows path uses subprocess")
    def test_unix_replaces_process_with_binary_and_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "lockyard"
            binary.write_text("#!/bin/sh\nexit 17\n")
            binary.chmod(0o755)
            with patch.object(cli, "binary_path", return_value=binary), patch(
                "sys.argv", ["lockyard", "status"]
            ), patch.object(cli.os, "execv", side_effect=OSError("exec intercepted")) as execv:
                with self.assertRaises(OSError):
                    cli.main()
                execv.assert_called_once_with(str(binary), [str(binary), "status"])

    @unittest.skipUnless(os.name == "nt", "the subprocess path is Windows-only")
    def test_windows_passes_arguments_and_child_code(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "lockyard.exe"
            binary.write_bytes(b"fake")
            with patch.object(cli, "binary_path", return_value=binary), patch(
                "sys.argv", ["lockyard", "status"]
            ), patch.object(cli.subprocess, "run", return_value=type("Done", (), {"returncode": 17})()) as run:
                self.assertEqual(cli.main(), 17)
                run.assert_called_once_with([str(binary), "status"], check=False)


if __name__ == "__main__":
    unittest.main()
