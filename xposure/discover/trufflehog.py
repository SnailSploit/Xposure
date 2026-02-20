"""TruffleHog integration — deep secrets scanning.

Wraps the trufflehog CLI binary to scan discovered content for secrets.
Runs as a background task alongside the main X-POSURE pipeline.
Supports scanning: URLs/web pages, git repos, and filesystem paths.
"""

import asyncio
import json
import shutil
from dataclasses import dataclass, field
from typing import AsyncGenerator, Optional

from ..config import Config
from ..core.models import Candidate, Source


@dataclass
class TruffleHogFinding:
    """A single TruffleHog finding."""
    detector_name: str = ""
    decoder_name: str = ""
    raw: str = ""
    raw_v2: str = ""
    verified: bool = False
    source_type: str = ""  # "web", "git", "filesystem"
    source_url: str = ""
    source_metadata: dict = field(default_factory=dict)
    extra_data: dict = field(default_factory=dict)

    def to_candidate(self) -> Candidate:
        """Convert to X-POSURE Candidate for the pipeline."""
        # Map trufflehog detector names to X-POSURE types
        cred_type = self._map_detector_to_type()
        value = self.raw_v2 or self.raw

        source = Source(
            type="trufflehog",
            url=self.source_url,
            path=self.source_metadata.get("file", None),
            line=self.source_metadata.get("line", None),
        )

        confidence = 0.9 if self.verified else 0.5

        return Candidate(
            type=cred_type,
            value=value,
            source=source,
            entropy=0.0,  # TruffleHog doesn't expose entropy
            context=json.dumps(self.extra_data)[:500] if self.extra_data else "",
            confidence=confidence,
        )

    def _map_detector_to_type(self) -> str:
        """Map trufflehog detector name to X-POSURE credential type."""
        name = self.detector_name.lower()
        mapping = {
            "aws": "aws_access_key",
            "github": "github_token",
            "gitlab": "gitlab_token",
            "slack": "slack_token",
            "stripe": "stripe_secret_key",
            "openai": "openai_api_key",
            "anthropic": "anthropic_api_key",
            "azure": "azure_client_secret",
            "gcp": "gcp_credentials",
            "mongodb": "database_url",
            "postgres": "database_url",
            "mysql": "database_url",
            "redis": "database_url",
            "sendgrid": "sendgrid_api_key",
            "twilio": "twilio_auth_token",
            "mailgun": "mailgun_api_key",
            "jwt": "jwt_token",
            "privatekey": "private_key",
            "heroku": "heroku_api_key",
            "dropbox": "dropbox_token",
            "discord": "discord_token",
            "telegram": "telegram_bot_token",
            "shopify": "shopify_token",
            "npm": "npm_token",
            "pypi": "pypi_token",
            "dockerhub": "docker_token",
            "digitalocean": "digitalocean_token",
            "firebase": "firebase_key",
            "supabase": "supabase_key",
        }
        for key, cred_type in mapping.items():
            if key in name:
                return cred_type
        return f"trufflehog_{name}"


class TruffleHogScanner:
    """Wraps trufflehog binary for deep secrets scanning."""

    def __init__(self, config: Config):
        self.config = config
        self.binary = shutil.which("trufflehog")
        self.stats = {
            "findings": 0,
            "verified": 0,
            "scanned_urls": 0,
            "errors": 0,
        }

    @property
    def available(self) -> bool:
        """Check if trufflehog is installed."""
        return self.binary is not None

    async def scan_urls(self, urls: list[str]) -> AsyncGenerator[TruffleHogFinding, None]:
        """Scan a list of URLs for secrets using trufflehog.

        TruffleHog 3.x supports `trufflehog filesystem --url` for web content,
        but primarily we use `trufflehog web` for URL scanning.
        """
        if not self.binary:
            return

        for url in urls:
            self.stats["scanned_urls"] += 1
            async for finding in self._run_trufflehog("web", url):
                yield finding

    async def scan_git_repo(self, repo_url: str) -> AsyncGenerator[TruffleHogFinding, None]:
        """Scan a git repository for secrets."""
        if not self.binary:
            return

        async for finding in self._run_trufflehog("git", repo_url):
            yield finding

    async def scan_target(self, target: str) -> AsyncGenerator[TruffleHogFinding, None]:
        """Scan a target domain — runs `trufflehog web` on the root."""
        if not self.binary:
            return

        target_url = target if target.startswith("http") else f"https://{target}"
        async for finding in self._run_trufflehog("web", target_url):
            yield finding

    async def _run_trufflehog(
        self, scan_type: str, target: str
    ) -> AsyncGenerator[TruffleHogFinding, None]:
        """Run trufflehog subprocess and stream JSON findings.

        Args:
            scan_type: "web", "git", or "filesystem".
            target: URL, repo URL, or path.
        """
        cmd = [
            self.binary,
            scan_type,
            "--json",
            "--no-update",
        ]

        # Add target based on scan type
        if scan_type == "web":
            cmd.extend(["--url", target])
        elif scan_type == "git":
            cmd.extend(["--url", target])
        elif scan_type == "filesystem":
            cmd.extend(["--directory", target])

        # Add verification flag
        if not self.config.verify:
            cmd.append("--only-verified=false")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            async for line in proc.stdout:
                decoded = line.decode().strip()
                if not decoded:
                    continue

                try:
                    data = json.loads(decoded)
                    finding = self._parse_finding(data, scan_type, target)
                    if finding:
                        self.stats["findings"] += 1
                        if finding.verified:
                            self.stats["verified"] += 1
                        yield finding
                except json.JSONDecodeError:
                    continue

            await proc.wait()

        except FileNotFoundError:
            if not self.config.quiet:
                print("[trufflehog] binary not found")
        except Exception as e:
            self.stats["errors"] += 1
            if not self.config.quiet:
                print(f"[trufflehog] error: {e}")

    def _parse_finding(
        self, data: dict, scan_type: str, target: str
    ) -> Optional[TruffleHogFinding]:
        """Parse a single trufflehog JSON output line."""
        # TruffleHog 3.x JSON format
        detector = data.get("DetectorName", data.get("detectorName", ""))
        if not detector:
            return None

        return TruffleHogFinding(
            detector_name=detector,
            decoder_name=data.get("DecoderName", data.get("decoderName", "")),
            raw=data.get("Raw", data.get("raw", "")),
            raw_v2=data.get("RawV2", data.get("rawV2", "")),
            verified=data.get("Verified", data.get("verified", False)),
            source_type=scan_type,
            source_url=target,
            source_metadata=data.get("SourceMetadata", data.get("sourceMetadata", {})),
            extra_data=data.get("ExtraData", data.get("extraData", {})),
        )

    def get_stats(self) -> dict:
        return dict(self.stats)
