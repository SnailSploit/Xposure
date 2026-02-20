#!/usr/bin/env python3
"""Tests for recursive crawl feature: fingerprints, crawler, resolver, shodan, AI analyzer, trufflehog."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

from xposure.config import Config
from xposure.core.models import (
    Candidate, Finding, InfraMapping, ScanStats, Severity, Source,
    VerificationStatus,
)
from xposure.discover.fingerprints import (
    ALL_FINGERPRINTS, BrowserFingerprint, FingerprintRotator,
)


# ── Fingerprint tests ────────────────────────────────────────────

def test_fingerprint_pool():
    """Test fingerprint pool has realistic browser profiles."""
    print("=" * 70)
    print("TEST: Fingerprint Pool")
    print("=" * 70)

    rotator = FingerprintRotator()
    print(f"\nPool size: {rotator.pool_size} fingerprints")
    assert rotator.pool_size >= 15, f"Expected >= 15 fingerprints, got {rotator.pool_size}"

    # Check all fingerprints have required fields
    for fp in ALL_FINGERPRINTS:
        assert fp.user_agent, "Missing user_agent"
        assert fp.accept, "Missing accept"
        assert fp.accept_language, "Missing accept_language"
        assert fp.accept_encoding, "Missing accept_encoding"
        assert "Mozilla" in fp.user_agent, f"Bad UA: {fp.user_agent}"

    # Verify browser diversity
    uas = [fp.user_agent for fp in ALL_FINGERPRINTS]
    has_chrome = any("Chrome" in ua and "Edg" not in ua for ua in uas)
    has_firefox = any("Firefox" in ua for ua in uas)
    has_safari = any("Safari" in ua and "Chrome" not in ua for ua in uas)
    has_edge = any("Edg" in ua for ua in uas)

    print(f"  Chrome:  {'yes' if has_chrome else 'NO'}")
    print(f"  Firefox: {'yes' if has_firefox else 'NO'}")
    print(f"  Safari:  {'yes' if has_safari else 'NO'}")
    print(f"  Edge:    {'yes' if has_edge else 'NO'}")

    assert has_chrome and has_firefox and has_safari and has_edge, \
        "Missing browser diversity"
    print("\nPASSED\n")


def test_fingerprint_rotation():
    """Test fingerprint rotator never returns same twice in a row."""
    print("=" * 70)
    print("TEST: Fingerprint Rotation")
    print("=" * 70)

    rotator = FingerprintRotator()
    last_ua = None
    consecutive_same = 0

    for i in range(100):
        fp = rotator.next()
        if fp.user_agent == last_ua:
            consecutive_same += 1
        last_ua = fp.user_agent

    print(f"\n  100 rotations, {consecutive_same} consecutive repeats")
    assert consecutive_same == 0, "Got consecutive same fingerprint"
    print("  PASSED\n")


def test_fingerprint_headers():
    """Test fingerprint produces valid HTTP headers."""
    print("=" * 70)
    print("TEST: Fingerprint Headers")
    print("=" * 70)

    rotator = FingerprintRotator()

    for _ in range(5):
        headers = rotator.next_headers()
        assert "User-Agent" in headers, "Missing User-Agent header"
        assert "Accept" in headers, "Missing Accept header"
        assert "Accept-Language" in headers, "Missing Accept-Language header"
        assert "Accept-Encoding" in headers, "Missing Accept-Encoding header"

        # Chrome/Edge should have Sec-CH-UA
        ua = headers["User-Agent"]
        if "Chrome" in ua:
            assert "Sec-CH-UA" in headers, f"Chrome UA missing Sec-CH-UA: {ua}"

    print("\n  Headers validated for 5 random fingerprints")
    print("  PASSED\n")


# ── Crawler tests ────────────────────────────────────────────────

def test_crawler_link_extraction():
    """Test the built-in crawler's link extraction."""
    print("=" * 70)
    print("TEST: Crawler Link Extraction")
    print("=" * 70)

    from xposure.discover.crawler import RecursiveCrawler

    config = Config(target="example.com")
    queue = asyncio.Queue()
    crawler = RecursiveCrawler(config, queue)

    html = '''
    <html>
    <head><link rel="stylesheet" href="/style.css"></head>
    <body>
        <a href="/about">About</a>
        <a href="https://example.com/contact">Contact</a>
        <a href="https://external.com/bad">External</a>
        <a href="javascript:void(0)">JS Link</a>
        <a href="mailto:test@example.com">Email</a>
        <script src="/js/app.js"></script>
        <img src="/logo.png">
        <a href="/api/v1/users">API</a>
        <a href="https://sub.example.com/page">Subdomain</a>
        <form action="/login" method="POST">
            <input type="text" name="user">
        </form>
    </body>
    </html>
    '''

    links = crawler._extract_links(html, "https://example.com", "example.com")

    print(f"\n  Extracted {len(links)} links:")
    for link in links:
        print(f"    {link}")

    # Should include same-domain links
    assert any("/about" in l for l in links), "Missing /about"
    assert any("/contact" in l for l in links), "Missing /contact"
    assert any("/api/v1/users" in l for l in links), "Missing /api/v1/users"
    assert any("/js/app.js" in l for l in links), "Missing /js/app.js"
    assert any("/login" in l for l in links), "Missing /login"
    assert any("sub.example.com" in l for l in links), "Missing subdomain"

    # Should exclude external, static, and non-http
    assert not any("external.com" in l for l in links), "Should exclude external"
    assert not any("logo.png" in l for l in links), "Should exclude .png"
    assert not any("style.css" in l for l in links), "Should exclude .css"
    assert not any("javascript:" in l for l in links), "Should exclude javascript:"
    assert not any("mailto:" in l for l in links), "Should exclude mailto:"

    print("  PASSED\n")


def test_crawler_stats():
    """Test crawler stats tracking."""
    print("=" * 70)
    print("TEST: Crawler Stats")
    print("=" * 70)

    from xposure.discover.crawler import RecursiveCrawler

    config = Config(target="example.com")
    queue = asyncio.Queue()
    crawler = RecursiveCrawler(config, queue)

    stats = crawler.get_stats()
    assert stats["pages_crawled"] == 0
    assert stats["urls_found"] == 0
    assert stats["errors"] == 0

    print(f"\n  Initial stats: {stats}")
    print("  PASSED\n")


# ── DNS Resolver tests ───────────────────────────────────────────

def test_resolver_model():
    """Test DNS resolution data models."""
    print("=" * 70)
    print("TEST: DNS Resolver Models")
    print("=" * 70)

    from xposure.discover.resolver import ResolvedHost

    host = ResolvedHost(
        domain="example.com",
        ips=["93.184.216.34"],
        ipv6=["2606:2800:220:1:248:1893:25c8:1946"],
        cnames=[],
        mx_records=["mx1.example.com"],
        txt_records=["v=spf1 -all"],
        reverse_dns="example.com",
    )

    d = host.to_dict()
    assert d["domain"] == "example.com"
    assert "93.184.216.34" in d["ips"]
    assert d["reverse_dns"] == "example.com"

    print(f"\n  ResolvedHost: {json.dumps(d, indent=2)}")
    print("  PASSED\n")


def test_resolver_unique_ips():
    """Test unique IP extraction from resolved hosts."""
    print("=" * 70)
    print("TEST: Resolver Unique IPs")
    print("=" * 70)

    from xposure.discover.resolver import BulkResolver, ResolvedHost

    config = Config(target="example.com")
    resolver = BulkResolver(config)

    resolved = {
        "example.com": ResolvedHost(domain="example.com", ips=["1.2.3.4", "5.6.7.8"]),
        "www.example.com": ResolvedHost(domain="www.example.com", ips=["1.2.3.4"]),
        "api.example.com": ResolvedHost(domain="api.example.com", ips=["9.10.11.12"]),
    }

    unique = resolver.get_unique_ips(resolved)
    print(f"\n  Unique IPs: {unique}")
    assert len(unique) == 3, f"Expected 3 unique IPs, got {len(unique)}"
    assert "1.2.3.4" in unique
    assert "5.6.7.8" in unique
    assert "9.10.11.12" in unique
    print("  PASSED\n")


# ── Shodan tests ─────────────────────────────────────────────────

def test_shodan_model():
    """Test Shodan data model."""
    print("=" * 70)
    print("TEST: Shodan Model")
    print("=" * 70)

    from xposure.discover.shodan import ShodanHostInfo

    host = ShodanHostInfo(
        ip="1.2.3.4",
        hostnames=["example.com"],
        os="Linux",
        organization="Example Corp",
        ports=[22, 80, 443, 3306],
        services=[{"port": 80, "product": "nginx"}],
        vulns=["CVE-2021-44228"],
    )

    d = host.to_dict()
    print(f"\n  ShodanHostInfo: {json.dumps(d, indent=2)}")

    assert host.has_critical_services, "Port 3306 should be critical"
    assert d["organization"] == "Example Corp"
    assert len(d["vulns"]) == 1

    # Non-critical host
    safe_host = ShodanHostInfo(ip="5.6.7.8", ports=[80, 443])
    assert not safe_host.has_critical_services, "80/443 should not be critical"

    print("  PASSED\n")


def test_shodan_parse():
    """Test Shodan response parsing."""
    print("=" * 70)
    print("TEST: Shodan Response Parsing")
    print("=" * 70)

    from xposure.discover.shodan import ShodanMapper

    config = Config(target="example.com")
    mapper = ShodanMapper(config, api_key="test_key")

    raw_response = {
        "ip_str": "1.2.3.4",
        "hostnames": ["example.com", "www.example.com"],
        "os": "Ubuntu",
        "org": "DigitalOcean",
        "isp": "DigitalOcean LLC",
        "asn": "AS14061",
        "country_name": "United States",
        "city": "New York",
        "ports": [22, 80, 443],
        "vulns": ["CVE-2021-44228", "CVE-2023-12345"],
        "tags": ["cloud"],
        "last_update": "2024-01-01T00:00:00",
        "data": [
            {
                "port": 80,
                "transport": "tcp",
                "product": "nginx",
                "version": "1.24.0",
                "data": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0",
                "http": {"title": "Example", "server": "nginx/1.24.0"},
            },
            {
                "port": 443,
                "transport": "tcp",
                "product": "nginx",
                "data": "HTTP/1.1 200 OK",
                "ssl": {
                    "cert": {
                        "issuer": {"O": "Let's Encrypt"},
                        "expires": "2025-01-01T00:00:00",
                    }
                },
            },
        ],
    }

    info = mapper._parse_host("1.2.3.4", raw_response)

    print(f"\n  Parsed: {info.ip}")
    print(f"  Hostnames: {info.hostnames}")
    print(f"  Ports: {info.ports}")
    print(f"  CVEs: {info.vulns}")
    print(f"  Services: {len(info.services)}")

    assert info.ip == "1.2.3.4"
    assert len(info.hostnames) == 2
    assert info.os == "Ubuntu"
    assert info.organization == "DigitalOcean"
    assert 22 in info.ports
    assert len(info.vulns) == 2
    assert len(info.services) == 2
    assert info.services[0]["product"] == "nginx"
    assert info.services[1].get("ssl_issuer") == "Let's Encrypt"

    print("  PASSED\n")


# ── TruffleHog tests ─────────────────────────────────────────────

def test_trufflehog_finding_to_candidate():
    """Test TruffleHog finding conversion to X-POSURE Candidate."""
    print("=" * 70)
    print("TEST: TruffleHog → Candidate Conversion")
    print("=" * 70)

    from xposure.discover.trufflehog import TruffleHogFinding

    finding = TruffleHogFinding(
        detector_name="AWS",
        raw="AKIAIOSFODNN7EXAMPLE",
        raw_v2="AKIAIOSFODNN7EXAMPLE",
        verified=True,
        source_type="web",
        source_url="https://example.com/config.js",
        source_metadata={"file": "config.js", "line": 42},
    )

    candidate = finding.to_candidate()

    print(f"\n  Type: {candidate.type}")
    print(f"  Value: {candidate.value}")
    print(f"  Source: {candidate.source.url}")
    print(f"  Confidence: {candidate.confidence}")

    assert candidate.type == "aws_access_key"
    assert candidate.value == "AKIAIOSFODNN7EXAMPLE"
    assert candidate.confidence == 0.9  # verified
    assert candidate.source.type == "trufflehog"

    # Unverified finding
    unverified = TruffleHogFinding(
        detector_name="GitHub",
        raw="ghp_abc123",
        verified=False,
    )
    unverified_candidate = unverified.to_candidate()
    assert unverified_candidate.confidence == 0.5  # not verified
    assert unverified_candidate.type == "github_token"

    print("  PASSED\n")


def test_trufflehog_detector_mapping():
    """Test detector name to credential type mapping."""
    print("=" * 70)
    print("TEST: TruffleHog Detector Mapping")
    print("=" * 70)

    from xposure.discover.trufflehog import TruffleHogFinding

    mappings = {
        "AWS": "aws_access_key",
        "GitHub": "github_token",
        "Slack": "slack_token",
        "Stripe": "stripe_secret_key",
        "OpenAI": "openai_api_key",
        "Anthropic": "anthropic_api_key",
        "MongoDB": "database_url",
        "JWT": "jwt_token",
        "PrivateKey": "private_key",
    }

    for detector, expected_type in mappings.items():
        finding = TruffleHogFinding(detector_name=detector, raw="test")
        candidate = finding.to_candidate()
        assert candidate.type == expected_type, \
            f"Detector '{detector}': expected '{expected_type}', got '{candidate.type}'"
        print(f"  {detector:15s} -> {candidate.type}")

    print("\n  PASSED\n")


# ── AI Analyzer tests ────────────────────────────────────────────

def test_ai_analyzer_prompt_building():
    """Test prompt construction for Anthropic analysis."""
    print("=" * 70)
    print("TEST: AI Analyzer Prompt Building")
    print("=" * 70)

    from xposure.correlate.ai_analyzer import AnthropicAnalyzer

    config = Config(target="example.com")
    analyzer = AnthropicAnalyzer(config, api_key="test_key")

    # Create test findings
    findings = [
        Finding(
            id="f1",
            credential_type="aws_access_key",
            value="AKIAIOSFODNN7EXAMPLE",
            masked_value="AKIA****MPLE",
            status=VerificationStatus.VERIFIED,
            identity="arn:aws:iam::123456:user/deploy",
            permissions=["s3:*", "ec2:*"],
            blast_radius=Severity.CRITICAL,
            environment="production",
            confidence=0.95,
            sources=[Source(type="js_file", url="https://example.com/app.js")],
        ),
    ]

    infra_data = {
        "1.2.3.4": {
            "hostnames": ["example.com"],
            "ports": [22, 80, 443, 3306],
            "vulns": ["CVE-2021-44228"],
            "organization": "AWS",
        }
    }

    dns_data = {
        "example.com": {
            "ips": ["1.2.3.4"],
            "mx_records": ["mx.example.com"],
        }
    }

    prompt = analyzer._build_prompt(findings, infra_data, dns_data)

    print(f"\n  Prompt length: {len(prompt)} chars")
    print(f"  Contains target: {'example.com' in prompt}")
    print(f"  Contains finding: {'aws_access_key' in prompt}")
    print(f"  Contains infra: {'CVE-2021-44228' in prompt}")
    print(f"  Contains DNS: {'mx.example.com' in prompt}")

    assert "example.com" in prompt
    assert "aws_access_key" in prompt
    assert "AKIA****MPLE" in prompt
    assert "CVE-2021-44228" in prompt
    assert "production" in prompt

    print("  PASSED\n")


def test_ai_analyzer_response_parsing():
    """Test parsing of Anthropic API response."""
    print("=" * 70)
    print("TEST: AI Analyzer Response Parsing")
    print("=" * 70)

    from xposure.correlate.ai_analyzer import AnthropicAnalyzer

    config = Config(target="example.com")
    analyzer = AnthropicAnalyzer(config, api_key="test_key")

    # Simulate Claude's JSON response
    raw_response = json.dumps({
        "risk_summary": "Critical: AWS production credentials exposed in public JS bundle.",
        "overall_risk_score": 9.5,
        "critical_findings": [
            {
                "finding": "AWS access key with full S3/EC2 permissions",
                "why_critical": "Production credentials with admin-level access",
                "exploit_scenario": "Attacker can access all S3 buckets and spawn EC2 instances",
            }
        ],
        "attack_chains": [
            {
                "chain": "JS bundle -> AWS key -> S3 data exfil -> lateral movement to EC2",
                "impact": "Full cloud account compromise",
                "likelihood": "high",
            }
        ],
        "infrastructure_risks": [
            {
                "risk": "MySQL port 3306 exposed to internet",
                "affected_ips": ["1.2.3.4"],
                "recommendation": "Restrict to VPC only",
            }
        ],
        "remediation_priorities": [
            {
                "priority": 1,
                "action": "Rotate AWS access key immediately",
                "finding_ids": ["f1"],
                "urgency": "immediate",
            }
        ],
    })

    analysis = analyzer._parse_response(raw_response)

    print(f"\n  Risk score: {analysis.overall_risk_score}/10")
    print(f"  Summary: {analysis.risk_summary[:80]}...")
    print(f"  Critical findings: {len(analysis.critical_findings)}")
    print(f"  Attack chains: {len(analysis.attack_chains)}")
    print(f"  Remediation items: {len(analysis.remediation_priorities)}")

    assert analysis.overall_risk_score == 9.5
    assert "AWS" in analysis.risk_summary
    assert len(analysis.critical_findings) == 1
    assert len(analysis.attack_chains) == 1
    assert analysis.remediation_priorities[0]["urgency"] == "immediate"

    # Test with markdown code fences
    fenced = f"```json\n{raw_response}\n```"
    analysis2 = analyzer._parse_response(fenced)
    assert analysis2.overall_risk_score == 9.5, "Failed to parse fenced JSON"

    print("  PASSED\n")


# ── InfraMapping model tests ─────────────────────────────────────

def test_infra_mapping_model():
    """Test InfraMapping data model."""
    print("=" * 70)
    print("TEST: InfraMapping Model")
    print("=" * 70)

    mapping = InfraMapping(
        domain_to_ips={"example.com": ["1.2.3.4"]},
        ip_to_shodan={"1.2.3.4": {"ports": [80, 443]}},
        unique_ips=["1.2.3.4"],
        total_open_ports=2,
        total_vulns=1,
    )

    d = mapping.to_dict()
    print(f"\n  {json.dumps(d, indent=2)}")

    assert d["unique_ips"] == ["1.2.3.4"]
    assert d["total_open_ports"] == 2
    assert d["total_vulns"] == 1
    print("  PASSED\n")


def test_scan_stats_crawl_fields():
    """Test ScanStats includes recursive crawl + enrichment fields."""
    print("=" * 70)
    print("TEST: ScanStats Crawl Fields")
    print("=" * 70)

    from datetime import datetime

    stats = ScanStats(
        target="example.com",
        start_time=datetime.now(),
        crawl_pages=150,
        crawl_urls_found=320,
        trufflehog_findings=5,
        dns_resolved=10,
        shodan_queried=8,
        ai_analyzed=True,
    )

    d = stats.to_dict()
    print(f"\n  Crawl stats: {d.get('recursive_crawl')}")
    print(f"  Enrichment stats: {d.get('enrichment')}")

    assert "recursive_crawl" in d
    assert d["recursive_crawl"]["pages_crawled"] == 150
    assert d["recursive_crawl"]["trufflehog_findings"] == 5
    assert "enrichment" in d
    assert d["enrichment"]["ai_analyzed"] is True

    # Without crawl stats, section should not appear
    stats2 = ScanStats(target="example.com", start_time=datetime.now())
    d2 = stats2.to_dict()
    assert "recursive_crawl" not in d2
    assert "enrichment" not in d2

    print("  PASSED\n")


# ── Config tests ─────────────────────────────────────────────────

def test_config_crawl_fields():
    """Test Config includes new recursive crawl fields."""
    print("=" * 70)
    print("TEST: Config Crawl Fields")
    print("=" * 70)

    config = Config(
        target="example.com",
        recursive_crawl=True,
        crawl_depth=10,
        crawl_max_pages=1000,
        crawl_min_sleep=2.0,
        crawl_max_sleep=5.0,
        use_trufflehog=True,
        shodan_key="test_shodan_key",
        anthropic_key="test_anthropic_key",
    )

    print(f"\n  recursive_crawl: {config.recursive_crawl}")
    print(f"  crawl_depth: {config.crawl_depth}")
    print(f"  crawl_max_pages: {config.crawl_max_pages}")
    print(f"  crawl_min_sleep: {config.crawl_min_sleep}")
    print(f"  crawl_max_sleep: {config.crawl_max_sleep}")
    print(f"  use_trufflehog: {config.use_trufflehog}")
    print(f"  shodan_key: {'set' if config.shodan_key else 'not set'}")
    print(f"  anthropic_key: {'set' if config.anthropic_key else 'not set'}")

    assert config.recursive_crawl is True
    assert config.crawl_depth == 10
    assert config.crawl_max_pages == 1000
    assert config.crawl_min_sleep == 2.0
    assert config.crawl_max_sleep == 5.0
    assert config.shodan_key == "test_shodan_key"
    assert config.anthropic_key == "test_anthropic_key"

    print("  PASSED\n")


# ── Runner ───────────────────────────────────────────────────────

def run_all():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("X-POSURE RECURSIVE CRAWL TESTS")
    print("=" * 70 + "\n")

    tests = [
        test_fingerprint_pool,
        test_fingerprint_rotation,
        test_fingerprint_headers,
        test_crawler_link_extraction,
        test_crawler_stats,
        test_resolver_model,
        test_resolver_unique_ips,
        test_shodan_model,
        test_shodan_parse,
        test_trufflehog_finding_to_candidate,
        test_trufflehog_detector_mapping,
        test_ai_analyzer_prompt_building,
        test_ai_analyzer_response_parsing,
        test_infra_mapping_model,
        test_scan_stats_crawl_fields,
        test_config_crawl_fields,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  FAILED: {e}\n")

    print("\n" + "=" * 70)
    print(f"RESULTS: {passed} passed, {failed} failed, {len(tests)} total")
    print("=" * 70)

    return failed == 0


if __name__ == "__main__":
    import sys
    success = run_all()
    sys.exit(0 if success else 1)
