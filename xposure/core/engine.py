"""X-POSURE main scanning engine."""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..config import Config
from ..state import ScanState, generate_scan_id
from .models import Finding, ScanStats, Candidate
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
    ):
        """
        Initialize the X-POSURE engine.

        Args:
            target: Target domain to scan
            github_token: GitHub token for dorking
            verify: Whether to perform active verification
            output_file: Path to output JSON file
            quiet: Minimal output mode
        """
        self.config = Config(
            target=target,
            github_token=github_token,
            verify=verify,
            output_file=output_file,
            quiet=quiet,
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
        self.dashboard = None

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
            self.dashboard = dashboard
            await dashboard.start()
            await self._run_scan()
        except KeyboardInterrupt:
            print("\n[x-posure] scan interrupted")
        finally:
            await dashboard.stop()
            self._finalize()

    async def _run_scan(self):
        """Run the actual scan."""
        print(f"[x-posure] target: {self.config.target}")
        print(f"[x-posure] scan_id: {self.scan_id}")

        # 1. Discovery Phase
        self._update_dashboard("discovery", "Mapping the surface")
        discovered_content = await self._discovery_phase()

        # 2. Extraction Phase
        self._update_dashboard("extraction", "Harvesting signals")
        await self._extraction_phase(discovered_content)

        # 3. Correlation Phase
        self._update_dashboard("correlation", "Linking intel")
        await self._correlation_phase()

        # 4. Verification Phase
        if self.config.verify:
            self._update_dashboard("verification", "Trust but verify")
            await self._verification_phase()
        else:
            self._update_dashboard("complete", "Verification skipped (user choice)")

        # Update stats
        self.stats.end_time = datetime.now()
        self._update_dashboard("complete", "Scan finished")

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

        # Run discovery modules concurrently
        tasks = []

        # Subdomain discovery
        if self.config.discover_subdomains:
            tasks.append(self._discover_subdomains())

        # Path discovery
        tasks.append(self._discover_paths())

        # Gather results
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)

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
        """Extract credentials from discovered content."""
        if not self.config.quiet:
            print("\n[extraction] analyzing content...")

        from ..rules.engine import RuleEngine
        from ..extract.decode import DecodeChain
        from ..extract.entropy import FalsePositiveDetector
        from ..core.models import Source

        rule_engine = RuleEngine()
        decoder = DecodeChain(max_depth=self.config.max_decode_depth)
        fp_detector = FalsePositiveDetector()

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
            len(urls_to_fetch) + 
            len(inline_scripts) + 
            len(config_files) + 
            len(source_maps) +
            len(github_results)
        )
        if not self.config.quiet:
            print(f"[extraction] analyzing {total_to_analyze} sources...")
            if config_files:
                print(f"  - {len(config_files)} config files")
            if source_maps:
                print(f"  - {len(source_maps)} source maps")
            if github_results:
                print(f"  - {len(github_results)} GitHub results")

        # Track filtered candidates
        filtered_count = 0

        # Helper function to scan content with FP detection
        async def scan_content(content: str, source: Source, label: str, source_type: str = ""):
            """Scan content for credentials with false positive filtering."""
            nonlocal filtered_count
            
            if not content or len(content) < 10:
                return
                
            # 1. Rules-based scan
            raw_candidates = list(rule_engine.scan(content, source))
            
            # 2. Filter false positives
            valid_candidates = []
            for candidate in raw_candidates:
                is_fp, reason = fp_detector.is_false_positive(
                    candidate.value,
                    candidate.context,
                    source_type or source.type
                )
                
                if is_fp:
                    filtered_count += 1
                    if self.config.verbose:
                        print(f"  [filtered] {candidate.type}: {reason}")
                    continue
                
                # Adjust confidence based on FP analysis
                adjustment = fp_detector.get_confidence_adjustment(
                    candidate.value,
                    candidate.context,
                    source_type or source.type
                )
                candidate.confidence = max(0.0, min(1.0, candidate.confidence + adjustment))
                
                valid_candidates.append(candidate)
            
            self.stats.candidates_found += len(valid_candidates)

            if valid_candidates:
                if not self.config.quiet:
                    print(f"[extract] found {len(valid_candidates)} candidates in {label}")
                
                for candidate in valid_candidates:
                    self.all_candidates.append(candidate)
                    if not self.config.quiet:
                        display_val = candidate.value[:30] + "..." if len(candidate.value) > 30 else candidate.value
                        conf = f"({candidate.confidence:.0%})" if candidate.confidence else ""
                        print(f"  [+] {candidate.type}: {display_val} {conf}")

            # 3. Try decoding encoded content
            try:
                sample_size = min(len(content), 5000)
                decoded_variants = list(decoder.decode_all(content[:sample_size]))
                self.stats.decoded_blobs += max(0, len(decoded_variants) - 1)

                for decoded_content, decode_path in decoded_variants[1:]:
                    if decode_path and decoded_content:
                        source_decoded = Source(
                            type='decoded',
                            url=source.url,
                            path=' -> '.join(decode_path),
                        )

                        decoded_candidates = list(rule_engine.scan(decoded_content, source_decoded))
                        
                        # Filter decoded candidates too
                        for candidate in decoded_candidates:
                            is_fp, _ = fp_detector.is_false_positive(candidate.value, candidate.context)
                            if not is_fp:
                                self.stats.candidates_found += 1
                                self.all_candidates.append(candidate)

                        if not self.config.quiet and decoded_candidates:
                            print(f"[decoded] found {len(decoded_candidates)} in {' -> '.join(decode_path)}")
            except Exception:
                pass

        # 1. Process config files first (highest priority)
        for config in config_files:
            content = config.get('content', '')
            url = config.get('url', 'unknown')
            file_type = config.get('metadata', {}).get('file_type', 'config')
            
            source = Source(type='config_file', url=url)
            await scan_content(content, source, f"config: {url}", source_type=file_type)

        # 2. Process source map content
        for source_map in source_maps:
            original_sources = source_map.get('original_sources', [])
            map_url = source_map.get('url', 'unknown')
            
            for orig in original_sources:
                content = orig.get('content')
                if not content:
                    continue
                    
                path = orig.get('path', 'unknown')
                source = Source(type='source_map', url=f"{map_url}:{path}")
                await scan_content(content, source, f"sourcemap: {path}", source_type='source_map')

        # 3. Process GitHub results
        for gh_result in github_results:
            content = gh_result.get('content', '')
            if not content:
                continue
                
            url = gh_result.get('url', 'unknown')
            repo = gh_result.get('metadata', {}).get('repo_name', '')
            
            source = Source(type='github', url=url)
            await scan_content(content, source, f"github: {repo}", source_type='github')

        # 4. Process inline scripts
        for inline in inline_scripts:
            content = inline.get('content', '')
            source_url = inline.get('source_url', 'unknown')
            
            source = Source(type='inline_script', url=source_url)
            await scan_content(content, source, f"inline: {source_url}", source_type='inline_script')

        # 5. Fetch and process external URLs
        for url in urls_to_fetch:
            try:
                content = await self._fetch_url_content(url)
                if not content:
                    continue

                source_type = 'js_file' if url.endswith('.js') or '/js/' in url else 'url'
                source = Source(type=source_type, url=url)

                self.graph.track_discovery(
                    source=Source(type='domain', url=f"https://{self.config.target}"),
                    discovered_url=url,
                    discovered_type=source_type,
                )

                await scan_content(content, source, url, source_type=source_type)

            except Exception as e:
                if self.config.verbose:
                    print(f"[extract] Error processing {url}: {e}")
                continue

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
        context_scores: dict[str, float] = {}
        for candidate in self.all_candidates:
            finding, is_new = self.deduplicator.add_or_merge(candidate)

            if is_new:
                unique_findings.append(finding)

                # Track in graph
                self.graph.track_finding(finding)

            # Track strongest context signal for this finding
            context_score = self.scorer.analyze_snippet_context(candidate.context)
            if finding.id not in context_scores:
                context_scores[finding.id] = context_score
            else:
                context_scores[finding.id] = max(context_scores[finding.id], context_score)

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

            # Calculate final confidence score
            final_score = self.scorer.calculate_score(
                finding=finding,
                is_paired=is_paired,
                context_quality=context_scores.get(finding.id, 0.7),
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

    async def _fetch_url_content(self, url: str) -> str:
        """Fetch content from a URL."""
        try:
            import aiohttp

            timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
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

    def export_json(self, output_file: str):
        """
        Export findings to JSON.

        Args:
            output_file: Path to output file
        """
        self.state.export(Path(output_file))

    def _update_dashboard(self, phase: str, detail: str = ""):
        """Send phase updates to the live dashboard if enabled."""
        if self.dashboard:
            try:
                self.dashboard.set_phase(phase, detail)
            except Exception:
                # Dashboard issues shouldn't break the scan
                pass
