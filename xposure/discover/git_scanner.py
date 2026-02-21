"""Git history scanner for X-POSURE v5.0.

Scans git repository history for secrets that were added in past commits.
Uses ``git`` subprocess calls directly (no gitpython dependency) to walk
diffs, extract added lines, and check whether secrets are still present
at HEAD.
"""

import asyncio
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import AsyncGenerator, Optional

from ..config import Config


@dataclass
class GitFinding:
    """A potential secret found in git history."""

    commit_hash: str = ""
    author: str = ""
    date: str = ""
    message: str = ""
    file_path: str = ""
    content: str = ""
    line_number: int = 0
    still_in_head: bool = False

    def to_dict(self) -> dict:
        return {
            "commit_hash": self.commit_hash,
            "author": self.author,
            "date": self.date,
            "message": self.message,
            "file_path": self.file_path,
            "content": self.content,
            "line_number": self.line_number,
            "still_in_head": self.still_in_head,
        }


class GitScanner:
    """Scan git repositories for secrets in commit history.

    This scanner is dependency-free beyond ``git`` being available on
    ``$PATH``.  It shells out to ``git log`` / ``git show`` via
    :mod:`asyncio.create_subprocess_exec`.

    Usage::

        scanner = GitScanner(config)

        # Local repo
        async for finding in scanner.scan_repo("/path/to/repo"):
            print(finding)

        # Remote repo (clones to tmp, scans, cleans up)
        async for finding in scanner.scan_remote("https://github.com/org/repo"):
            print(finding)

        # Incremental (only commits after a known point)
        async for finding in scanner.scan_incremental("/path/to/repo", "abc123"):
            print(finding)
    """

    # Maximum diff output size to process (bytes) -- protects against
    # enormous diffs consuming all memory.
    MAX_DIFF_SIZE: int = 50 * 1024 * 1024  # 50 MiB

    def __init__(self, config: Config, max_diff_size: int = 50 * 1024 * 1024):
        self.config = config
        self.MAX_DIFF_SIZE = max_diff_size
        self.stats = {
            "commits_scanned": 0,
            "files_scanned": 0,
            "findings": 0,
            "errors": 0,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan_repo(
        self, repo_path: str
    ) -> AsyncGenerator[dict, None]:
        """Scan all history of a local repository.

        Args:
            repo_path: Absolute path to a git checkout.

        Yields:
            :class:`GitFinding` dicts for every diff hunk containing
            added lines.
        """
        async for finding in self._scan(repo_path, since_commit=None):
            yield finding

    async def scan_remote(
        self, url: str
    ) -> AsyncGenerator[dict, None]:
        """Clone a remote repository to a temp directory, scan, and clean up.

        Args:
            url: Git-cloneable URL (HTTPS or SSH).

        Yields:
            :class:`GitFinding` dicts.
        """
        tmp_dir = tempfile.mkdtemp(prefix="xposure_git_")

        try:
            # Clone (bare to save space)
            clone_rc = await self._run_git(
                ["git", "clone", "--bare", "--quiet", url, tmp_dir],
                cwd=None,
            )
            if clone_rc != 0:
                self.stats["errors"] += 1
                if not self.config.quiet:
                    print(f"[git_scanner] failed to clone {url}")
                return

            async for finding in self._scan(tmp_dir, since_commit=None):
                yield finding

        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    async def scan_incremental(
        self, repo_path: str, since_commit: str
    ) -> AsyncGenerator[dict, None]:
        """Scan only commits reachable from HEAD but not from *since_commit*.

        Args:
            repo_path: Absolute path to a git checkout.
            since_commit: The last known-good commit hash.

        Yields:
            :class:`GitFinding` dicts.
        """
        async for finding in self._scan(repo_path, since_commit=since_commit):
            yield finding

    # ------------------------------------------------------------------
    # Core scanning logic
    # ------------------------------------------------------------------

    async def _scan(
        self,
        repo_path: str,
        since_commit: Optional[str],
    ) -> AsyncGenerator[dict, None]:
        """Run ``git log --all --diff-filter=A -p`` and parse output.

        We stream the subprocess output line-by-line so we never need to
        hold the entire diff in memory at once.
        """
        cmd = [
            "git", "log",
            "--all",
            "--diff-filter=A",
            "-p",
            "--format=XPOSURE_COMMIT:%H|%an|%aI|%s",
        ]

        if since_commit:
            cmd.append(f"{since_commit}..HEAD")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=repo_path,
            )
        except FileNotFoundError:
            self.stats["errors"] += 1
            if not self.config.quiet:
                print("[git_scanner] git binary not found on PATH")
            return

        # Parsing state
        current_commit = ""
        current_author = ""
        current_date = ""
        current_message = ""
        current_file: Optional[str] = None
        line_number = 0
        hunk_content_lines: list[str] = []
        bytes_read = 0

        async for raw_line in proc.stdout:
            bytes_read += len(raw_line)
            if bytes_read > self.MAX_DIFF_SIZE:
                if not self.config.quiet:
                    print(
                        "[git_scanner] max diff size reached, stopping early"
                    )
                break

            line = raw_line.decode(errors="replace").rstrip("\n")

            # --- Commit header ---
            if line.startswith("XPOSURE_COMMIT:"):
                # Flush any buffered hunk from the previous file
                if hunk_content_lines and current_file:
                    finding = await self._make_finding(
                        repo_path,
                        current_commit,
                        current_author,
                        current_date,
                        current_message,
                        current_file,
                        hunk_content_lines,
                        line_number,
                    )
                    if finding:
                        yield finding

                hunk_content_lines = []
                current_file = None
                line_number = 0

                parts = line[len("XPOSURE_COMMIT:"):].split("|", 3)
                current_commit = parts[0] if len(parts) > 0 else ""
                current_author = parts[1] if len(parts) > 1 else ""
                current_date = parts[2] if len(parts) > 2 else ""
                current_message = parts[3] if len(parts) > 3 else ""
                self.stats["commits_scanned"] += 1
                continue

            # --- Diff file header ---
            if line.startswith("diff --git "):
                # Flush previous file hunk
                if hunk_content_lines and current_file:
                    finding = await self._make_finding(
                        repo_path,
                        current_commit,
                        current_author,
                        current_date,
                        current_message,
                        current_file,
                        hunk_content_lines,
                        line_number,
                    )
                    if finding:
                        yield finding

                hunk_content_lines = []
                line_number = 0

                # Extract file path: "diff --git a/path b/path"
                parts = line.split(" b/", 1)
                current_file = parts[1] if len(parts) > 1 else None
                if current_file:
                    self.stats["files_scanned"] += 1
                continue

            # --- Hunk header (@@ ... @@) ---
            if line.startswith("@@"):
                # Parse starting line number from @@ -X,Y +Z,W @@
                try:
                    plus_part = line.split("+")[1].split(" ")[0]
                    line_number = int(plus_part.split(",")[0])
                except (IndexError, ValueError):
                    line_number = 0
                continue

            # --- Added lines ---
            if line.startswith("+") and not line.startswith("+++"):
                hunk_content_lines.append(line[1:])  # Strip leading "+"
                continue

        # Flush final hunk
        if hunk_content_lines and current_file:
            finding = await self._make_finding(
                repo_path,
                current_commit,
                current_author,
                current_date,
                current_message,
                current_file,
                hunk_content_lines,
                line_number,
            )
            if finding:
                yield finding

        await proc.wait()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _make_finding(
        self,
        repo_path: str,
        commit_hash: str,
        author: str,
        date: str,
        message: str,
        file_path: str,
        content_lines: list[str],
        line_number: int,
    ) -> Optional[dict]:
        """Build a :class:`GitFinding` dict and check HEAD presence."""
        content = "\n".join(content_lines)
        if not content.strip():
            return None

        still_in_head = await self._is_in_head(repo_path, file_path)

        self.stats["findings"] += 1

        finding = GitFinding(
            commit_hash=commit_hash,
            author=author,
            date=date,
            message=message[:200],
            file_path=file_path,
            content=content[:4096],  # cap for safety
            line_number=line_number,
            still_in_head=still_in_head,
        )
        return finding.to_dict()

    async def _is_in_head(self, repo_path: str, file_path: str) -> bool:
        """Check if *file_path* still exists at HEAD."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "show", f"HEAD:{file_path}",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                cwd=repo_path,
            )
            rc = await asyncio.wait_for(proc.wait(), timeout=5.0)
            return rc == 0
        except Exception:
            return False

    @staticmethod
    async def _run_git(cmd: list[str], cwd: Optional[str]) -> int:
        """Run a git command and return the exit code."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                cwd=cwd,
            )
            return await asyncio.wait_for(proc.wait(), timeout=300)
        except Exception:
            return 1

    def get_stats(self) -> dict:
        return dict(self.stats)
