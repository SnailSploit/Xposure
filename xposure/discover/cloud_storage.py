"""Cloud storage enumeration for X-POSURE v5.0.

Derives likely bucket / container names from a target domain and probes
AWS S3, Google Cloud Storage, and Azure Blob Storage to determine whether
those buckets exist and are publicly accessible.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import aiohttp

from ..config import Config


@dataclass
class BucketInfo:
    """Information about a discovered cloud storage bucket."""

    provider: str  # "aws", "gcs", "azure"
    name: str
    accessible: bool = False
    objects_count: int = 0
    url: str = ""
    status_code: Optional[int] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "name": self.name,
            "accessible": self.accessible,
            "objects_count": self.objects_count,
            "url": self.url,
            "status_code": self.status_code,
            "error": self.error,
        }


# Common bucket-name derivation suffixes
_BUCKET_SUFFIXES: list[str] = [
    "",
    "-assets",
    "-static",
    "-media",
    "-uploads",
    "-public",
    "-private",
    "-backup",
    "-backups",
    "-data",
    "-dev",
    "-staging",
    "-prod",
    "-production",
    "-logs",
    "-config",
    "-cdn",
    "-images",
    "-files",
    "-docs",
    "-archive",
    "-db",
    "-dump",
    "-test",
    "-internal",
    "-web",
    "-app",
    "-api",
    "-storage",
    "-s3",
]

# Common bucket-name derivation prefixes
_BUCKET_PREFIXES: list[str] = [
    "",
    "dev-",
    "staging-",
    "prod-",
    "backup-",
    "internal-",
    "test-",
]


class CloudStorageEnumerator:
    """Enumerate cloud storage buckets for a target domain.

    Usage::

        enumerator = CloudStorageEnumerator(config)
        results = await enumerator.enumerate("example.com")
        for bucket in results:
            print(bucket["provider"], bucket["name"], bucket["accessible"])
    """

    # Probe timeout per request
    PROBE_TIMEOUT: float = 5.0

    # Maximum concurrent probes
    MAX_CONCURRENT: int = 20

    def __init__(
        self,
        config: Config,
        probe_timeout: float = 5.0,
        max_concurrent: int = 20,
    ):
        self.config = config
        self.PROBE_TIMEOUT = probe_timeout
        self.MAX_CONCURRENT = max_concurrent
        self.stats = {
            "buckets_checked": 0,
            "buckets_found": 0,
            "buckets_accessible": 0,
            "errors": 0,
        }

    async def enumerate(self, domain: str) -> list[dict]:
        """Derive bucket names and probe all three cloud providers.

        Args:
            domain: Target domain (e.g. ``"example.com"``).

        Returns:
            List of :class:`BucketInfo` dicts for every bucket that
            returned a non-404 response (i.e. bucket exists).
        """
        bucket_names = self._derive_bucket_names(domain)

        if not self.config.quiet:
            print(
                f"[cloud_storage] probing {len(bucket_names)} bucket names "
                f"across 3 providers..."
            )

        sem = asyncio.Semaphore(self.MAX_CONCURRENT)
        tasks: list[asyncio.Task] = []

        timeout = aiohttp.ClientTimeout(total=self.PROBE_TIMEOUT)
        connector = aiohttp.TCPConnector(ssl=False)

        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={"User-Agent": self.config.user_agent},
        ) as session:
            for name in bucket_names:
                tasks.append(
                    asyncio.ensure_future(
                        self._probe_all_providers(session, name, sem)
                    )
                )

            all_results = await asyncio.gather(
                *tasks, return_exceptions=True
            )

        # Flatten results
        found: list[dict] = []
        for result in all_results:
            if isinstance(result, list):
                found.extend(result)

        if not self.config.quiet:
            print(
                f"[cloud_storage] found {len(found)} existing buckets "
                f"({self.stats['buckets_accessible']} accessible)"
            )

        return found

    # ------------------------------------------------------------------
    # Bucket name derivation
    # ------------------------------------------------------------------

    def _derive_bucket_names(self, domain: str) -> list[str]:
        """Generate candidate bucket names from a domain.

        Strips TLD, replaces dots with hyphens, and applies common
        prefix/suffix patterns.
        """
        names: set[str] = set()

        # Base variants from the domain
        # "sub.example.com" -> ["sub.example.com", "sub-example-com",
        #                       "sub.example", "sub-example",
        #                       "example.com", "example-com", "example"]
        parts = domain.split(".")
        base_variants: list[str] = []

        # Full domain as-is and hyphenated
        base_variants.append(domain)
        base_variants.append(domain.replace(".", "-"))

        # Without TLD
        if len(parts) > 1:
            no_tld = ".".join(parts[:-1])
            base_variants.append(no_tld)
            base_variants.append(no_tld.replace(".", "-"))

        # Just the SLD (second-level domain)
        if len(parts) >= 2:
            sld = parts[-2]
            base_variants.append(sld)

        # Apply suffixes and prefixes
        for base in base_variants:
            for suffix in _BUCKET_SUFFIXES:
                names.add(f"{base}{suffix}")
            for prefix in _BUCKET_PREFIXES:
                if prefix:  # skip empty to avoid duplicates
                    names.add(f"{prefix}{base}")

        # Filter out invalid bucket names (too short or too long)
        valid = [
            n for n in names
            if 3 <= len(n) <= 63 and not n.startswith("-") and not n.endswith("-")
        ]

        return sorted(set(valid))

    # ------------------------------------------------------------------
    # Probing
    # ------------------------------------------------------------------

    async def _probe_all_providers(
        self,
        session: aiohttp.ClientSession,
        bucket_name: str,
        sem: asyncio.Semaphore,
    ) -> list[dict]:
        """Probe a single bucket name across AWS, GCS, and Azure."""
        results: list[dict] = []

        async with sem:
            # AWS S3
            aws = await self._probe_s3(session, bucket_name)
            if aws:
                results.append(aws.to_dict())

            # GCS
            gcs = await self._probe_gcs(session, bucket_name)
            if gcs:
                results.append(gcs.to_dict())

            # Azure Blob
            azure = await self._probe_azure(session, bucket_name)
            if azure:
                results.append(azure.to_dict())

        return results

    async def _probe_s3(
        self, session: aiohttp.ClientSession, bucket: str
    ) -> Optional[BucketInfo]:
        """HEAD request to ``{bucket}.s3.amazonaws.com``."""
        url = f"https://{bucket}.s3.amazonaws.com"
        self.stats["buckets_checked"] += 1

        try:
            async with session.head(url, allow_redirects=True) as resp:
                if resp.status == 404:
                    return None  # Bucket does not exist

                info = BucketInfo(
                    provider="aws",
                    name=bucket,
                    url=url,
                    status_code=resp.status,
                )

                if resp.status == 200:
                    info.accessible = True
                    self.stats["buckets_accessible"] += 1
                    # Try to list objects
                    info.objects_count = await self._count_s3_objects(
                        session, bucket
                    )
                elif resp.status == 403:
                    # Bucket exists but is not publicly accessible
                    info.accessible = False

                self.stats["buckets_found"] += 1
                return info

        except (asyncio.TimeoutError, aiohttp.ClientError):
            return None
        except Exception:
            self.stats["errors"] += 1
            return None

    async def _count_s3_objects(
        self, session: aiohttp.ClientSession, bucket: str
    ) -> int:
        """Attempt to list S3 bucket objects and return a count."""
        url = f"https://{bucket}.s3.amazonaws.com/?list-type=2&max-keys=10"
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    # Count <Key> elements
                    return body.count("<Key>")
        except Exception:
            pass
        return 0

    async def _probe_gcs(
        self, session: aiohttp.ClientSession, bucket: str
    ) -> Optional[BucketInfo]:
        """HEAD request to ``storage.googleapis.com/{bucket}``."""
        url = f"https://storage.googleapis.com/{bucket}"
        self.stats["buckets_checked"] += 1

        try:
            async with session.head(url, allow_redirects=True) as resp:
                if resp.status == 404:
                    return None

                info = BucketInfo(
                    provider="gcs",
                    name=bucket,
                    url=url,
                    status_code=resp.status,
                )

                if resp.status == 200:
                    info.accessible = True
                    self.stats["buckets_accessible"] += 1
                elif resp.status == 403:
                    info.accessible = False

                self.stats["buckets_found"] += 1
                return info

        except (asyncio.TimeoutError, aiohttp.ClientError):
            return None
        except Exception:
            self.stats["errors"] += 1
            return None

    async def _probe_azure(
        self, session: aiohttp.ClientSession, bucket: str
    ) -> Optional[BucketInfo]:
        """HEAD request to ``{bucket}.blob.core.windows.net``."""
        # Azure storage account names are 3-24 chars, lowercase + digits only
        sanitized = bucket.replace("-", "").replace(".", "")[:24]
        if len(sanitized) < 3 or not sanitized.isalnum():
            return None

        url = f"https://{sanitized}.blob.core.windows.net"
        self.stats["buckets_checked"] += 1

        try:
            async with session.head(url, allow_redirects=True) as resp:
                if resp.status == 404:
                    return None

                # Azure returns various non-404 codes for existing accounts
                info = BucketInfo(
                    provider="azure",
                    name=sanitized,
                    url=url,
                    status_code=resp.status,
                )

                if resp.status == 200:
                    info.accessible = True
                    self.stats["buckets_accessible"] += 1
                elif resp.status in (400, 403):
                    # Account exists but not accessible
                    info.accessible = False

                self.stats["buckets_found"] += 1
                return info

        except (asyncio.TimeoutError, aiohttp.ClientError):
            return None
        except Exception:
            self.stats["errors"] += 1
            return None

    def get_stats(self) -> dict:
        return dict(self.stats)
