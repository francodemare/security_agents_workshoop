"""
Subprocess execution runner with timeouts and basic environment sanitization.
"""

import os
import signal
import subprocess
import time
from typing import Dict, List, Optional
from asap.core.types import ExecutionResult


class SubprocessRunner:
    """Executes shell commands within a bounded workspace and strict timeouts."""

    # Sensitive environment variables to strip from execution unless explicitly authorized
    DEFAULT_STRIP_ENV = {
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GITHUB_TOKEN",
        "SSH_AUTH_SOCK",
    }

    def __init__(self, workspace_dir: str, default_timeout_s: float = 30.0):
        self.workspace_dir = os.path.abspath(workspace_dir)
        self.default_timeout_s = default_timeout_s

    def run(
        self,
        command: str,
        timeout: Optional[float] = None,
        extra_env: Optional[Dict[str, str]] = None,
    ) -> ExecutionResult:
        """Runs a bash command inside the workspace with process-group cleanup on timeout."""
        timeout_s = timeout or self.default_timeout_s

        # Build sanitized environment
        env = dict(os.environ)
        for key in self.DEFAULT_STRIP_ENV:
            env.pop(key, None)
        if extra_env:
            env.update(extra_env)

        start = time.perf_counter()
        proc = subprocess.Popen(
            ["bash", "-c", command],
            cwd=self.workspace_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout_s)
            duration_ms = (time.perf_counter() - start) * 1000.0
            return ExecutionResult(
                exit_code=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                timed_out=False,
            )
        except subprocess.TimeoutExpired:
            # Terminate the entire process group so no child/zombie processes survive
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
            stdout, stderr = proc.communicate()
            duration_ms = (time.perf_counter() - start) * 1000.0
            return ExecutionResult(
                exit_code=-1,
                stdout=stdout or "",
                stderr=(stderr or "") + f"\n[ASAP Timeout] Execution exceeded {timeout_s}s (process group terminated)",
                duration_ms=duration_ms,
                timed_out=True,
            )
