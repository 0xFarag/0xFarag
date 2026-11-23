"""© Nasser Aldin Farag (0xFarag). All rights reserved."""
from contextlib import redirect_stderr
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from authzledger.cli import main


class RbacCommandTests(unittest.TestCase):
    def test_optional_runtime_missing_or_older(self):
        with patch("authzledger.rbac_cli.shutil.which", return_value=None), redirect_stderr(io.StringIO()) as err:
            self.assertEqual(main(["rbac", "--help"]), 2)
        self.assertIn("Node.js 22", err.getvalue())
        old = subprocess.CompletedProcess([], 0, b"v20.19.0\n", b"")
        with (patch("authzledger.rbac_cli.shutil.which", return_value="/example/node"),
              patch("authzledger.rbac_cli.subprocess.run", return_value=old) as run,
              redirect_stderr(io.StringIO())):
            self.assertEqual(main(["rbac", "--help"]), 2)
            self.assertEqual(run.call_count, 1)

    def test_arguments_are_forwarded_unchanged_to_shipped_script(self):
        version = subprocess.CompletedProcess([], 0, b"v22.1.2\n", b"")
        evaluated = subprocess.CompletedProcess([], 7)
        arguments = ["evaluate", "a file; $(example).json", "named(request).json", "--literal-test-arg"]
        with (patch("authzledger.rbac_cli.shutil.which", return_value="/example/node"),
              patch("authzledger.rbac_cli.subprocess.run", side_effect=[version, evaluated]) as run):
            self.assertEqual(main(["rbac", *arguments]), 7)
        launch = run.call_args_list[-1]
        program, script, *rest = launch.args[0]
        self.assertEqual(program, "/example/node")
        self.assertEqual(Path(script).parts[-3:], ("authzledger", "rbac", "cli.mjs"))
        self.assertEqual(rest, arguments)
        self.assertFalse(launch.kwargs.get("shell", False))
