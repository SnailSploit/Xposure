"""X-POSURE main scanning engine."""

import asyncio
import math
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..config import Config
from ..state import ScanState, generate_scan_id
from .models import Finding, ScanStats, Candidate, Severity, InfraMapping
from .graph import ContentGraph
from ..correlate.dedup import Deduplicator
from ..correlate.pairing import CredentialPairer
from ..correlate.confidence import ConfidenceScorer


class XPosureEngine:
    """Main X-POSURE scanning engine."""

    def __init__(
        self,
        target: str,
        github_token: Optional[str] = None,
        verify: bool = True,
        output_file: Optional[str] = None,
        quiet: bool = False,
        recursive_crawl: bool = False,
        crawl_depth: int = 5,
        crawl_max_pages: int = 500,
        crawl_min_sleep: float = 1.0,
        crawl_max_sleep: float = 3.0,
        use_trufflehog: bool = True,
        shodan_key: Optional[str] = None,
        anthropic_key: Optional[str] = None,
    ):
        self.config = Config(
            target=target,
            github_token=github_token,
            verify=verify,
            output_file=output_file,
            quiet=quiet,
            recursive_crawl=recursive_crawl,
            crawl_depth=crawl_depth,
            crawl_max_pages=crawl_max_pages,
            crawl_min_sleep=crawl_min_sleep,
            crawl_max_sleep=crawl_max_sleep,
            use_trufflehog=use_trufflehog,
            shodan_key=shodan_key,
            anthropic_key=anthropic_key,
        )

        # Generate scan ID
        self.scan_id = generate_scan_id(target)

        # Initialize state
        state_file = self.config.get_state_file(self.scan_id)
        self.state = ScanState(self.scan_id, state_file)

        # Initialize stats
        self.stats = ScanStats(
            target=target,
            start_time=datetime.now(),
        )

        # Initialize correlation components
        self.graph = ContentGraph()
        self.deduplicator = Deduplicator()
        self.pairer = CredentialPairer()
        self.scorer = ConfidenceScorer()

        # Store all candidates for correlation
        self.all_candidates = []
        self.findings = []

        # Infrastructure mapping (populated by enrichment phases)
        self.infra_mapping = InfraMapping()
        self.ai_analysis = None

        # Background crawl shared queue
        self._crawl_queue: Optional[asyncio.Queue] = None
        self._crawl_task: Optional[asyncio.Task] = None

    async def run_quiet(self):
        """Run scan in quiet mode (no live dashboard)."""
        print(f"[x-posure] scanning {self.config.target}...")

        try:
            await self._run_scan()
        except KeyboardInterrupt:
            print("\n[x-posure] scan interrupted")
        finally:
            self._finalize()

    async def run_with_dashboard(self):
        """Run scan with live dashboard."""
        # Import here to avoid dependency issues if Rich not installed
        try:
            from ..output.console import LiveDashboard
        except ImportError:
            print("Warning: Rich not installed, falling back to quiet mode")
            await self.run_quiet()
            return

        dashboard = LiveDashboard(self.config, self.state, self.stats)

        try:
            await dashboard.start()
            await self._run_scan()
        except KeyboardInterrupt:
            print("\n[x-posure] scan interrupted")
        finally:
            dashboard.stop()
            self._finalize()

    async def _run_scan(self):
        """Run the actual scan."""
        print(f"[x-posure] target: {self.config.target}")
        print(f"[x-posure] scan_id: {self.scan_id}")

        if self.config.recursive_crawl:
            print(f"[x-posure] mode: recursive crawl (depth={self.config.crawl_depth})")

        # Start background crawl if -rc is enabled
        # It feeds URLs into extraction while normal discovery runs
        if self.config.recursive_crawl:
            self._crawl_queue = asyncio.Queue()
            self._crawl_task = asyncio.create_task(self._background_crawl())

        # 1. Discovery Phase (normal pipeline — always runs)
        discovered_content = await self._discovery_phase()

        # 2. Extraction Phase
        await self._extraction_phase(discovered_content)

        # 2b. Drain background crawl results into extraction
        if self.config.recursive_crawl and self._crawl_task:
            await self._drain_crawl_results()

        # 3. Correlation Phase
        await self._correlation_phase()

        # 4. Verification Phase
        if self.config.verify:
            await self._verification_phase()

        # 5. Enrichment Phases (when -rc is enabled)
        if self.config.recursive_crawl:
            await self._enrichment_pipeline()

        # Update stats
        self.stats.end_time = datetime.now()

    async def _discovery_phase(self) -> dict:
        """Run discovery modules to find attack surface."""
        if not self.config.quiet:
            print("\n[discovery] starting reconnaissance...")

        discovered_urls = []
        discovered_content = {
            'urls': [],
            'js_data': {'external_urls': [], 'inline_content': []},
            'paths': [],
            'configs': [],
            'source_maps': [],
            'github_results': [],
        }

        # Run discovery modules concurrently with an overall timeout
        tasks = []

        # Subdomain discovery
        if self.config.discover_subdomains:
            tasks.append(self._discover_subdomains())

        # Path discovery
        tasks.append(self._discover_paths())

        # Gather results (5-minute overall timeout for initial discovery)
        if tasks:
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=300,
                )
            except asyncio.TimeoutError:
                if not self.config.quiet:
                    print("[discovery] initial discovery timed out after 5 minutes")
                results = []

            # Flatten results
            for result in results:
                if isinstance(result, list):
                    discovered_urls.extend(result)
                    discovered_content['urls'].extend(result)

        # JavaScript discovery (uses discovered URLs)
        if self.config.discover_js:
            js_data = await self._discover_js_files(discovered_urls)
            total_js = len(js_data['external_urls']) + len(js_data['inline_content'])
            self.stats.js_files_found = total_js
            discovered_content['js_data'] = js_data

        discovered_content['paths'] = discovered_urls

        if not self.config.quiet:
            print(f"[discovery] found {self.stats.subdomains_found} subdomains")
            print(f"[discovery] found {self.stats.js_files_found} js files")

        # Config file discovery
        config_results = await self._discover_configs(discovered_urls)
        discovered_content['configs'] = config_results
        if not self.config.quiet and config_results:
            print(f"[discovery] found {len(config_results)} config files")

        # Source map discovery
        js_urls = discovered_content['js_data'].get('external_urls', [])
        if js_urls:
            source_maps = await self._discover_source_maps(js_urls)
            discovered_content['source_maps'] = source_maps
            if not self.config.quiet and source_maps:
                print(f"[discovery] found {len(source_maps)} source maps")

        # GitHub dorking (if token available)
        if self.config.github_token:
            github_results = await self._github_dork()
            discovered_content['github_results'] = github_results
            if not self.config.quiet and github_results:
                print(f"[discovery] found {len(github_results)} GitHub results")

        return discovered_content

    async def _discover_subdomains(self) -> list[str]:
        """Discover subdomains."""
        from ..discover.subdomains import SubdomainDiscoverer

        subdomains = []

        async with SubdomainDiscoverer(self.config) as discoverer:
            async for result in discoverer.discover():
                # Check if already seen
                if not self.state.mark_seen_url(result['url']):
                    continue

                subdomains.append(result['url'])
                self.stats.subdomains_found += 1

                if not self.config.quiet:
                    print(f"[subdomain] {result['subdomain']}")

        return subdomains

    async def _discover_paths(self) -> list[str]:
        """Discover interesting paths."""
        from ..discover.paths import PathDiscoverer

        paths = []

        async with PathDiscoverer(self.config) as discoverer:
            async for result in discoverer.discover():
                # Check if already seen
                if not self.state.mark_seen_url(result['url']):
                    continue

                paths.append(result['url'])

                if not self.config.quiet:
                    print(f"[path] {result['url']}")

        return paths

    async def _discover_js_files(self, urls: list[str]) -> dict:
        """Discover JavaScript files from URLs."""
        from ..discover.js import JSDiscoverer

        js_data = {
            'external_urls': [],
            'inline_content': [],  # Store inline script content directly
        }

        # Use target root if no URLs provided
        if not urls:
            urls = [f"https://{self.config.target}"]

        async with JSDiscoverer(self.config) as discoverer:
            async for result in discoverer.discover(start_urls=urls[:20]):  # Increased limit
                # Check if already seen
                if not self.state.mark_seen_url(result['url']):
                    continue

                if result.get('metadata', {}).get('inline'):
                    # Store inline script content directly
                    if result.get('content'):
                        js_data['inline_content'].append({
                            'content': result['content'],
                            'source_url': result['metadata']['found_in'],
                        })
                    if not self.config.quiet:
                        print(f"[js] inline script in {result['metadata']['found_in']}")
                else:
                    # External JS file - store URL to fetch later
                    js_data['external_urls'].append(result['url'])
                    if not self.config.quiet:
                        print(f"[js] {result['url']}")

        return js_data

    async def _discover_configs(self, discovered_urls: list[str]) -> list[dict]:
        """Discover configuration files."""
        from ..discover.configs import ConfigDiscoverer
        
        configs = []
        
        try:
            async with ConfigDiscoverer(self.config) as discoverer:
                async for result in discoverer.discover(subdomains=discovered_urls[:10]):
                    if not self.state.mark_seen_url(result['url']):
                        continue
                    
                    configs.append(result)
                    
                    if not self.config.quiet:
                        score = result.get('metadata', {}).get('interest_score', 0)
                        print(f"[config] {result['url']} (score: {score:.2f})")
        except Exception as e:
            if self.config.verbose:
                print(f"[config] Error: {e}")
        
        return configs

    async def _discover_source_maps(self, js_urls: list[str]) -> list[dict]:
        """Discover and parse source maps."""
        from ..discover.sourcemaps import SourceMapDiscoverer
        
        source_maps = []
        
        try:
            async with SourceMapDiscoverer(self.config) as discoverer:
                async for result in discoverer.discover(js_urls=js_urls):
                    source_maps.append(result)
                    
                    if not self.config.quiet:
                        sources_count = result.get('metadata', {}).get('sources_count', 0)
                        has_content = result.get('metadata', {}).get('has_content', False)
                        content_marker = "✓" if has_content else "○"
                        print(f"[sourcemap] {result['url']} ({sources_count} sources) {content_marker}")
        except Exception as e:
            if self.config.verbose:
                print(f"[sourcemap] Error: {e}")
        
        return source_maps

    async def _github_dork(self) -> list[dict]:
        """Search GitHub for exposed secrets."""
        from ..discover.github import GitHubDorker
        
        results = []
        
        if not self.config.github_token:
            return results
        
        try:
            async with GitHubDorker(self.config, self.config.github_token) as dorker:
                # Try to detect org name from domain
                org_name = GitHubDorker.detect_org_from_domain(self.config.target)
                
                if not self.config.quiet:
                    print(f"[github] searching for {self.config.target}...")
                
                async for result in dorker.discover(org_name=org_name):
                    results.append(result)
                    
                    if not self.config.quiet:
                        repo = result.get('metadata', {}).get('repo_name', '')
                        path = result.get('metadata', {}).get('file_path', '')
                        print(f"[github] {repo}: {path}")
        except Exception as e:
            if self.config.verbose:
                print(f"[github] Error: {e}")
        
        return results

    async def _extraction_phase(self, discovered_content: dict):
        """Extract credentials from discovered content.

        Uses a ProcessPoolExecutor to parallelize CPU-bound work (regex
        scanning, entropy analysis, decode chains) across multiple cores.
        """
        if not self.config.quiet:
            print("\n[extraction] analyzing content...")

        import asyncio
        import os
        from ..extract.parallel import ParallelExtractor
        from ..core.models import Source

        # Get JS data
        js_data = discovered_content.get('js_data', {'external_urls': [], 'inline_content': []})
        external_js_urls = js_data.get('external_urls', [])
        inline_scripts = js_data.get('inline_content', [])

        # Get config files
        config_files = discovered_content.get('configs', [])

        # Get source maps
        source_maps = discovered_content.get('source_maps', [])

        # Get GitHub results
        github_results = discovered_content.get('github_results', [])

        # Collect URLs to fetch (paths + external JS)
        urls_to_fetch = []
        urls_to_fetch.extend(external_js_urls)
        urls_to_fetch.extend(discovered_content.get('paths', []))

        # Add base target URLs
        urls_to_fetch.append(f"https://{self.config.target}")
        urls_to_fetch.append(f"https://www.{self.config.target}")

        # Deduplicate
        urls_to_fetch = list(dict.fromkeys(urls_to_fetch))

        total_to_analyze = (
            len(urls_to_fetch)
            + len(inline_scripts)
            + len(config_files)
            + len(source_maps)
            + len(github_results)
        )
        if not self.config.quiet:
            print(f"[extraction] analyzing {total_to_analyze} sources...")
            if config_files:
                print(f"  - {len(config_files)} config files")
            if source_maps:
                print(f"  - {len(source_maps)} source maps")
            if github_results:
                print(f"  - {len(github_results)} GitHub results")

        # ── Phase A: Collect all content to scan ─────────────────────
        # Each item is (content, Source, label, source_type_hint)
        work_items: list[tuple[str, Source, str, str]] = []

        # 1. Config files (highest priority)
        for config in config_files:
            content = config.get('content', '')
            url = config.get('url', 'unknown')
            file_type = config.get('metadata', {}).get('file_type', 'config')
            work_items.append((content, Source(type='config_file', url=url), f"config: {url}", file_type))

        # 2. Source map content
        for source_map in source_maps:
            original_sources = source_map.get('original_sources', [])
            map_url = source_map.get('url', 'unknown')
            for orig in original_sources:
                content = orig.get('content')
                if not content:
                    continue
                path = orig.get('path', 'unknown')
                work_items.append((content, Source(type='source_map', url=f"{map_url}:{path}"), f"sourcemap: {path}", 'source_map'))

        # 3. GitHub results
        for gh_result in github_results:
            content = gh_result.get('content', '')
            if not content:
                continue
            url = gh_result.get('url', 'unknown')
            repo = gh_result.get('metadata', {}).get('repo_name', '')
            work_items.append((content, Source(type='github', url=url), f"github: {repo}", 'github'))

        # 4. Inline scripts
        for inline in inline_scripts:
            content = inline.get('content', '')
            source_url = inline.get('source_url', 'unknown')
            work_items.append((content, Source(type='inline_script', url=source_url), f"inline: {source_url}", 'inline_script'))

        # 5. Fetch external URLs (async I/O, then CPU extraction)
        fetch_tasks = []
        for url in urls_to_fetch:
            fetch_tasks.append(self._fetch_url_content(url))

        fetched_contents = await asyncio.gather(*fetch_tasks, return_exceptions=True)

        for url, result in zip(urls_to_fetch, fetched_contents):
            if isinstance(result, Exception) or not result:
                continue
            source_type = 'js_file' if url.endswith('.js') or '/js/' in url else 'url'
            self.graph.track_discovery(
                source=Source(type='domain', url=f"https://{self.config.target}"),
                discovered_url=url,
                discovered_type=source_type,
            )
            work_items.append((result, Source(type=source_type, url=url), url, source_type))

        # ── Phase B: Parallel CPU extraction ─────────────────────────
        # Use min(cpu_count, 4) workers to avoid over-subscribing on
        # small machines while still bypassing the GIL on larger ones.
        workers = min(os.cpu_count() or 2, 4)

        if not self.config.quiet:
            print(f"[extraction] parallel extraction with {workers} workers...")

        loop = asyncio.get_event_loop()
        filtered_count = 0

        with ParallelExtractor(
            workers=workers,
            max_decode_depth=getattr(self.config, 'max_decode_depth', 5),
            verbose=getattr(self.config, 'verbose', False),
        ) as extractor:
            futures = []
            for content, source, label, source_type_hint in work_items:
                fut = extractor.submit(content, source, label, source_type_hint)
                futures.append(fut)

            # Collect results (blocks until all workers finish)
            results = await loop.run_in_executor(None, extractor.collect, futures)

        # ── Phase C: Merge results into engine state ─────────────────
        for result in results:
            filtered_count += result.get('filtered_count', 0)
            self.stats.decoded_blobs += result.get('decoded_blobs', 0)

            for cand_dict in result.get('candidates', []):
                source = Source(
                    type=cand_dict['source_type'],
                    url=cand_dict['source_url'],
                    path=cand_dict.get('source_path', ''),
                )
                candidate = Candidate(
                    type=cand_dict['type'],
                    value=cand_dict['value'],
                    source=source,
                    entropy=cand_dict['entropy'],
                    context=cand_dict['context'],
                    confidence=cand_dict['confidence'],
                )
                self.all_candidates.append(candidate)
                self.stats.candidates_found += 1

            label = result.get('label', '')
            n = len(result.get('candidates', []))
            if n > 0 and not self.config.quiet:
                print(f"[extract] found {n} candidates in {label}")

        if not self.config.quiet:
            print(f"[extraction] found {self.stats.candidates_found} total candidates")
            if filtered_count > 0:
                print(f"[extraction] filtered {filtered_count} false positives")
            print(f"[extraction] decoded {self.stats.decoded_blobs} encoded blobs")

    async def _correlation_phase(self):
        """Correlate candidates into findings with pairing and confidence scoring."""
        if not self.config.quiet:
            print("\n[correlation] analyzing relationships...")

        # 1. Deduplicate candidates into findings
        unique_findings = []
        for candidate in self.all_candidates:
            finding, is_new = self.deduplicator.add_or_merge(candidate)

            if is_new:
                unique_findings.append(finding)

                # Track in graph
                self.graph.track_finding(finding)

        if not self.config.quiet:
            print(f"[dedup] {len(self.all_candidates)} candidates -> {len(unique_findings)} unique findings")

        # 2. Find credential pairs
        for candidate in self.all_candidates:
            self.pairer.add_candidate(candidate)

        pairs = self.pairer.find_pairs()

        if not self.config.quiet and pairs:
            print(f"[pairing] found {len(pairs)} credential pairs")

        # Link pairs in graph
        for cand1, cand2 in pairs:
            # Get findings for these candidates
            finding1 = self.deduplicator.get_finding(cand1.value, cand1.type)
            finding2 = self.deduplicator.get_finding(cand2.value, cand2.type)

            if finding1 and finding2:
                self.graph.link_pair(finding1, finding2)

                # Mark as paired in metadata
                if 'paired' not in finding1.metadata:
                    finding1.metadata['paired'] = True
                if 'paired' not in finding2.metadata:
                    finding2.metadata['paired'] = True

        # 3. Score all findings with confidence
        paired_finding_ids = set()
        for cand1, cand2 in pairs:
            finding1 = self.deduplicator.get_finding(cand1.value, cand1.type)
            finding2 = self.deduplicator.get_finding(cand2.value, cand2.type)
            if finding1:
                paired_finding_ids.add(finding1.id)
            if finding2:
                paired_finding_ids.add(finding2.id)

        for finding in unique_findings:
            is_paired = finding.id in paired_finding_ids

            # Analyze context quality from sources (instead of hardcoding 0.7)
            context_quality = 0.5  # Default if no context available
            context_qualities = []
            for source in finding.sources:
                if source.raw_context and finding.value:
                    # Find position of value in context
                    position = source.raw_context.find(finding.value)
                    if position >= 0:
                        qual = self.scorer.analyze_context_quality(
                            content=source.raw_context,
                            position=position,
                            value=finding.value,
                        )
                        context_qualities.append(qual)

            if context_qualities:
                context_quality = sum(context_qualities) / len(context_qualities)

            # Calculate final confidence score
            final_score = self.scorer.calculate_score(
                finding=finding,
                is_paired=is_paired,
                context_quality=context_quality,
            )

            # Update finding confidence
            finding.confidence = final_score

        # 4. Store findings
        self.findings = unique_findings

        # 5. Update stats
        self.stats.unverified_findings = len(unique_findings)

        if not self.config.quiet:
            dedup_stats = self.deduplicator.get_stats()
            graph_stats = self.graph.get_stats()
            score_stats = self.scorer.get_stats()

            print(f"[correlation] {dedup_stats['unique_findings']} unique findings")
            print(f"[correlation] {dedup_stats['multi_source_findings']} from multiple sources")
            print(f"[correlation] avg confidence: {score_stats.get('avg_score', 0):.2f}")
            print(f"[correlation] graph nodes: {graph_stats['total_nodes']}, edges: {graph_stats['total_edges']}")

    async def _verification_phase(self):
        """Verify credentials to determine validity, identity, and permissions."""
        if not self.config.quiet:
            print("\n[verification] validating credentials...")

        from ..verify.coordinator import VerifierCoordinator

        # Initialize verifier coordinator
        coordinator = VerifierCoordinator(
            timeout=self.config.request_timeout,
            max_concurrent=self.config.max_concurrent_requests,
            passive_only=False,
        )

        # Verify findings
        verified_results = await coordinator.verify_findings(self.findings)

        if not self.config.quiet:
            print(f"[verification] verified {len(verified_results)} findings")

        # Update findings with verification results
        for finding, result in verified_results:
            finding.status = result.status
            finding.verification_method = result.method
            finding.identity = result.identity
            finding.permissions = result.permissions or []
            finding.can_pivot_to = result.can_pivot_to or []
            finding.blast_radius = result.blast_radius
            finding.environment = result.environment

            # Add verification metadata to finding metadata
            if result.metadata:
                finding.metadata.update({'verification': result.metadata})

            # Store error if verification failed
            if result.error:
                finding.metadata['verification_error'] = result.error

        # Update stats
        stats = coordinator.get_stats()
        self.stats.verified_findings = stats.get('verified', 0)
        self.stats.invalid_findings = stats.get('invalid', 0)
        self.stats.error_findings = stats.get('errors', 0)
        self.stats.unverified_findings = len(self.findings) - self.stats.verified_findings - self.stats.invalid_findings

        if not self.config.quiet:
            print(f"[verification] {self.stats.verified_findings} valid credentials")
            print(f"[verification] {self.stats.invalid_findings} invalid credentials")
            print(f"[verification] {self.stats.error_findings} verification errors")

            # Show high-value findings
            high_value = [f for f in self.findings if f.status.value == 'verified' and f.blast_radius in [Severity.CRITICAL, Severity.HIGH]]

            if high_value:
                print(f"\n[!] {len(high_value)} HIGH-VALUE credentials found:")
                for finding in high_value[:5]:  # Show first 5
                    print(f"  [{finding.credential_type}] {finding.identity or 'Unknown'} ({finding.blast_radius.value})")

    # ── Background recursive crawl ──────────────────────────────────

    async def _background_crawl(self):
        """Run recursive crawl + trufflehog in the background.

        Feeds discovered URLs into self._crawl_queue. The main pipeline
        drains this queue after its own discovery/extraction phases.
        """
        from ..discover.crawler import RecursiveCrawler
        from ..discover.trufflehog import TruffleHogScanner

        if not self.config.quiet:
            print("\n[crawl] starting background recursive crawl...")

        crawler = RecursiveCrawler(
            config=self.config,
            url_queue=self._crawl_queue,
            max_depth=self.config.crawl_depth,
            max_pages=self.config.crawl_max_pages,
            workers=self.config.crawl_workers,
            min_sleep=self.config.crawl_min_sleep,
            max_sleep=self.config.crawl_max_sleep,
        )

        crawl_urls = []
        try:
            async for result in crawler.crawl():
                crawl_urls.append(result.url)
                if not self.config.quiet and len(crawl_urls) % 25 == 0:
                    print(f"[crawl] {len(crawl_urls)} pages crawled...")
        except Exception as e:
            if not self.config.quiet:
                print(f"[crawl] error: {e}")

        crawl_stats = crawler.get_stats()
        self.stats.crawl_pages = crawl_stats.get("pages_crawled", 0)
        self.stats.crawl_urls_found = crawl_stats.get("urls_found", 0)

        if not self.config.quiet:
            print(f"[crawl] finished: {self.stats.crawl_pages} pages, "
                  f"{self.stats.crawl_urls_found} URLs ({crawl_stats.get('backend', 'unknown')})")

        # Run TruffleHog on crawled URLs
        if self.config.use_trufflehog:
            thog = TruffleHogScanner(self.config)
            if thog.available:
                if not self.config.quiet:
                    print("[trufflehog] scanning crawled URLs...")
                try:
                    async for finding in thog.scan_target(self.config.target):
                        candidate = finding.to_candidate()
                        self.all_candidates.append(candidate)
                        self.stats.trufflehog_findings += 1
                        if not self.config.quiet:
                            verified_tag = " [VERIFIED]" if finding.verified else ""
                            print(f"[trufflehog] {finding.detector_name}: "
                                  f"{finding.raw[:40]}...{verified_tag}")
                except Exception as e:
                    if not self.config.quiet:
                        print(f"[trufflehog] error: {e}")

                thog_stats = thog.get_stats()
                if not self.config.quiet:
                    print(f"[trufflehog] {thog_stats['findings']} findings "
                          f"({thog_stats['verified']} verified)")
            else:
                if not self.config.quiet:
                    print("[trufflehog] not installed, skipping (install: brew install trufflehog)")

        # Signal end of crawl queue
        await self._crawl_queue.put(None)

    async def _drain_crawl_results(self):
        """Wait for background crawl to finish, then extract secrets from crawled URLs."""
        if not self._crawl_task:
            return

        if not self.config.quiet:
            print("\n[crawl] waiting for background crawl to finish...")

        # Wait for crawl task to complete
        try:
            await asyncio.wait_for(self._crawl_task, timeout=600)  # 10 min max
        except asyncio.TimeoutError:
            if not self.config.quiet:
                print("[crawl] background crawl timed out, continuing with results so far")
            self._crawl_task.cancel()
            try:
                await self._crawl_task
            except asyncio.CancelledError:
                pass

        # Drain any remaining URLs from the queue and run extraction on them
        from ..rules.engine import RuleEngine
        from ..extract.entropy import FalsePositiveDetector
        from .models import Source

        rule_engine = RuleEngine()
        fp_detector = FalsePositiveDetector()
        crawled_count = 0

        while not self._crawl_queue.empty():
            url = self._crawl_queue.get_nowait()
            if url is None:
                break

            # Skip if already processed in normal pipeline
            if not self.state.mark_seen_url(url):
                continue

            crawled_count += 1

            # Fetch and extract
            try:
                content = await self._fetch_url_content(url)
                if not content or len(content) < 10:
                    continue

                source = Source(type='crawled', url=url)
                raw_candidates = list(rule_engine.scan(content, source))

                for candidate in raw_candidates:
                    is_fp, _ = fp_detector.is_false_positive(
                        candidate.value, candidate.context
                    )
                    if not is_fp:
                        self.all_candidates.append(candidate)
                        self.stats.candidates_found += 1
                        if not self.config.quiet:
                            display = candidate.value[:30] + "..." if len(candidate.value) > 30 else candidate.value
                            print(f"[crawl-extract] {candidate.type}: {display}")

            except Exception:
                continue

        if not self.config.quiet and crawled_count > 0:
            print(f"[crawl-extract] processed {crawled_count} additional URLs from crawl")

    # ── Enrichment pipeline (DNS → Shodan → Anthropic) ───────────

    async def _enrichment_pipeline(self):
        """Post-scan enrichment: resolve IPs, query Shodan, run AI analysis."""
        if not self.config.quiet:
            print("\n[enrichment] starting infrastructure mapping...")

        # Collect all unique domains from findings + discovery
        domains = self._collect_domains()
        if not domains:
            if not self.config.quiet:
                print("[enrichment] no domains to resolve")
            return

        # 1. DNS Resolution
        dns_data = await self._resolve_phase(domains)

        # 2. Shodan (if key provided)
        infra_data = None
        if self.config.shodan_key:
            infra_data = await self._shodan_phase(dns_data)

        # 3. Anthropic AI Analysis (if key provided)
        if self.config.anthropic_key:
            await self._ai_analysis_phase(infra_data, dns_data)

    def _collect_domains(self) -> list[str]:
        """Collect unique domains from all scan sources."""
        from urllib.parse import urlparse

        domains = set()
        domains.add(self.config.target)
        domains.add(f"www.{self.config.target}")

        # From findings
        for finding in self.findings:
            for source in finding.sources:
                try:
                    parsed = urlparse(source.url)
                    if parsed.hostname:
                        domains.add(parsed.hostname)
                except Exception:
                    pass

        # From state (all seen URLs)
        for url in self.state.get_seen_urls():
            try:
                parsed = urlparse(url)
                if parsed.hostname:
                    domains.add(parsed.hostname)
            except Exception:
                pass

        return sorted(domains)

    async def _resolve_phase(self, domains: list[str]) -> dict:
        """Resolve domains to IPs."""
        from ..discover.resolver import BulkResolver

        if not self.config.quiet:
            print(f"[dns] resolving {len(domains)} domains...")

        resolver = BulkResolver(self.config)
        resolved = await resolver.resolve_domains(domains)

        # Store in infra mapping
        for domain, host in resolved.items():
            self.infra_mapping.dns_records[domain] = host.to_dict()
            if host.ips:
                self.infra_mapping.domain_to_ips[domain] = host.ips

        unique_ips = resolver.get_unique_ips(resolved)
        self.infra_mapping.unique_ips = unique_ips
        self.stats.dns_resolved = len(resolved)

        if not self.config.quiet:
            stats = resolver.get_stats()
            print(f"[dns] resolved {stats['resolved']} domains -> {stats['unique_ips']} unique IPs")
            for domain, host in list(resolved.items())[:10]:
                if host.ips:
                    print(f"  {domain} -> {', '.join(host.ips)}")

        return resolved

    async def _shodan_phase(self, dns_data: dict) -> Optional[dict]:
        """Query Shodan for infrastructure mapping."""
        from ..discover.shodan import ShodanMapper

        unique_ips = self.infra_mapping.unique_ips
        if not unique_ips:
            if not self.config.quiet:
                print("[shodan] no IPs to query")
            return None

        if not self.config.quiet:
            print(f"\n[shodan] querying {len(unique_ips)} IPs...")

        mapper = ShodanMapper(self.config, self.config.shodan_key)
        results = await mapper.map_ips(unique_ips)

        # Store in infra mapping
        total_ports = 0
        total_vulns = 0
        for ip, info in results.items():
            info_dict = info.to_dict()
            self.infra_mapping.ip_to_shodan[ip] = info_dict
            total_ports += len(info.ports)
            total_vulns += len(info.vulns)

        self.infra_mapping.total_open_ports = total_ports
        self.infra_mapping.total_vulns = total_vulns
        self.stats.shodan_queried = len(results)

        if not self.config.quiet:
            stats = mapper.get_stats()
            print(f"[shodan] queried {stats['queried']} IPs, "
                  f"{stats['found']} found, {stats['vulns_total']} CVEs")

            # Show critical findings
            for ip, info in results.items():
                if info.has_critical_services:
                    print(f"  [!] {ip}: critical services on ports {info.ports}")
                if info.vulns:
                    print(f"  [!] {ip}: {len(info.vulns)} CVEs ({', '.join(info.vulns[:3])})")

        return results

    async def _ai_analysis_phase(self, infra_data: Optional[dict], dns_data: Optional[dict]):
        """Run Anthropic Claude analysis on findings + infrastructure."""
        from ..correlate.ai_analyzer import AnthropicAnalyzer

        if not self.config.quiet:
            print("\n[ai] running Anthropic analysis...")

        analyzer = AnthropicAnalyzer(self.config, self.config.anthropic_key)

        # Prepare infra data dicts
        infra_dict = None
        if infra_data:
            infra_dict = {
                ip: (info.to_dict() if hasattr(info, 'to_dict') else info)
                for ip, info in infra_data.items()
            }

        dns_dict = None
        if dns_data:
            dns_dict = {
                domain: (host.to_dict() if hasattr(host, 'to_dict') else host)
                for domain, host in dns_data.items()
            }

        analysis = await analyzer.analyze(
            findings=self.findings,
            infra_data=infra_dict,
            dns_data=dns_dict,
        )

        self.ai_analysis = analysis
        self.stats.ai_analyzed = True

        if analysis.error:
            if not self.config.quiet:
                print(f"[ai] error: {analysis.error}")
            return

        if not self.config.quiet:
            print(f"\n[ai] Risk Score: {analysis.overall_risk_score}/10")
            print(f"[ai] {analysis.risk_summary}")

            if analysis.critical_findings:
                print(f"\n[ai] Critical Findings ({len(analysis.critical_findings)}):")
                for cf in analysis.critical_findings[:5]:
                    print(f"  - {cf.get('finding', 'N/A')}")
                    print(f"    Why: {cf.get('why_critical', 'N/A')}")

            if analysis.attack_chains:
                print(f"\n[ai] Attack Chains ({len(analysis.attack_chains)}):")
                for chain in analysis.attack_chains[:3]:
                    print(f"  - {chain.get('chain', 'N/A')}")
                    print(f"    Impact: {chain.get('impact', 'N/A')}")

            if analysis.remediation_priorities:
                print(f"\n[ai] Remediation Priorities:")
                for rem in analysis.remediation_priorities[:5]:
                    urgency = rem.get('urgency', 'N/A')
                    print(f"  {rem.get('priority', '?')}. [{urgency}] {rem.get('action', 'N/A')}")

    @staticmethod
    def _calculate_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    async def _fetch_url_content(self, url: str) -> str:
        """Fetch content from a URL."""
        try:
            import aiohttp

            timeout = aiohttp.ClientTimeout(
                total=self.config.request_timeout,
                connect=min(self.config.request_timeout, 10),
                sock_connect=min(self.config.request_timeout, 10),
            )
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers={'User-Agent': self.config.user_agent}) as response:
                    if response.status == 200:
                        return await response.text()
        except Exception:
            pass

        return ""

    def _finalize(self):
        """Finalize scan and save state."""
        self.stats.end_time = datetime.now()
        self.state.update_stats(self.stats)
        self.state.save()

        # Print summary
        if not self.config.quiet:
            self._print_summary()

    def _print_summary(self):
        """Print scan summary."""
        print("\n" + "=" * 70)
        print("SCAN COMPLETE")
        print("=" * 70)

        if self.stats.end_time:
            duration = (self.stats.end_time - self.stats.start_time).total_seconds()
            print(f"Duration: {duration:.1f}s")

        print(f"\nFindings:")
        print(f"  Verified:    {self.stats.verified_findings}")
        print(f"  Unverified:  {self.stats.unverified_findings}")
        print(f"  Invalid:     {self.stats.invalid_findings}")
        print(f"  Errors:      {self.stats.error_findings}")

        total = (
            self.stats.verified_findings +
            self.stats.unverified_findings +
            self.stats.invalid_findings +
            self.stats.error_findings
        )
        print(f"  Total:       {total}")

        # Recursive crawl stats
        if self.stats.crawl_pages or self.stats.crawl_urls_found:
            print(f"\nRecursive Crawl:")
            print(f"  Pages crawled:       {self.stats.crawl_pages}")
            print(f"  URLs discovered:     {self.stats.crawl_urls_found}")
            if self.stats.trufflehog_findings:
                print(f"  TruffleHog findings: {self.stats.trufflehog_findings}")

        # Enrichment stats
        if self.stats.dns_resolved or self.stats.shodan_queried or self.stats.ai_analyzed:
            print(f"\nEnrichment:")
            if self.stats.dns_resolved:
                print(f"  DNS resolved:    {self.stats.dns_resolved} domains -> "
                      f"{len(self.infra_mapping.unique_ips)} IPs")
            if self.stats.shodan_queried:
                print(f"  Shodan queried:  {self.stats.shodan_queried} IPs | "
                      f"{self.infra_mapping.total_open_ports} ports | "
                      f"{self.infra_mapping.total_vulns} CVEs")
            if self.stats.ai_analyzed and self.ai_analysis:
                score = self.ai_analysis.overall_risk_score
                print(f"  AI risk score:   {score}/10")

    def export_json(self, output_file: str):
        """
        Export findings to JSON.

        Args:
            output_file: Path to output file
        """
        import json

        # Build comprehensive export
        export_data = {
            "scan_id": self.scan_id,
            "stats": self.stats.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
        }

        # Include infra mapping if available
        if self.infra_mapping.unique_ips:
            export_data["infrastructure"] = self.infra_mapping.to_dict()

        # Include AI analysis if available
        if self.ai_analysis:
            export_data["ai_analysis"] = self.ai_analysis.to_dict()

        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)

        # Also save to state
        self.state.export(Path(output_file))
