"""CLI must observe the same capability boundaries as the HTTP scanner."""
import contextlib
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from caner.__main__ import main


class TestPortableCLI(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'win32', 'requires the real Windows API')
    def test_windows_working_set_is_measured(self):
        from caner.platforms.windows import self_rss_mb
        self.assertGreater(self_rss_mb(), 0)

    def test_fresh_import_without_unix_sysconf(self):
        code = "import os; delattr(os, 'sysconf') if hasattr(os, 'sysconf') else None; import caner.__main__; from caner.platforms import generic, linux, darwin, windows"
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True,
                                cwd=Path(__file__).resolve().parents[1])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_once_skips_unsupported_scanners(self):
        from caner.platforms import windows
        output = io.StringIO()
        with patch('caner.platforms._backend', windows), \
             patch('caner.procscan.scan', side_effect=AssertionError('Linux-only proc scan')), \
             patch('caner.crashscan.scan', side_effect=AssertionError('Linux-only crash scan')), \
             patch('caner.netscan.scan', return_value={'findings': []}), \
             contextlib.redirect_stdout(output):
            self.assertEqual(main(['--once']), 0)
        data = json.loads(output.getvalue())
        self.assertEqual(data['meta']['platform']['backend'], 'windows')
        self.assertIn('unsupported', data['proc'])
        self.assertIn('unsupported', data['crash'])
        self.assertEqual(data['net'], {'findings': []})
