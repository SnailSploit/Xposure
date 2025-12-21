#!/usr/bin/env python3
"""Test correlation module."""

from xposure.correlate.dedup import Deduplicator
from xposure.correlate.pairing import CredentialPairer
from xposure.correlate.confidence import ConfidenceScorer
from xposure.core.graph import ContentGraph
from xposure.core.models import Candidate, Source, Severity


def test_deduplication():
    """Test deduplication with multi-source evidence."""
    print("=" * 70)
    print("TEST: Deduplication")
    print("=" * 70)

    dedup = Deduplicator()

    # Create same credential from different sources
    source1 = Source(type='url', url='https://example.com/config.js')
    source2 = Source(type='url', url='https://example.com/env.js')
    source3 = Source(type='decoded', url='https://example.com/bundle.js', path='base64')

    candidate1 = Candidate(
        type='aws_access_key',
        value='AKIAIOSFODNN7EXAMPLE',
        source=source1,
        entropy=4.5,
        context='AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
        confidence=0.8,
    )

    candidate2 = Candidate(
        type='aws_access_key',
        value='AKIAIOSFODNN7EXAMPLE',  # Same value
        source=source2,
        entropy=4.5,
        context='accessKey: AKIAIOSFODNN7EXAMPLE',
        confidence=0.8,
    )

    candidate3 = Candidate(
        type='aws_access_key',
        value='AKIAIOSFODNN7EXAMPLE',  # Same value again
        source=source3,
        entropy=4.5,
        context='key=AKIAIOSFODNN7EXAMPLE',
        confidence=0.8,
    )

    # Different credential
    candidate4 = Candidate(
        type='github_token',
        value='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',
        source=source1,
        entropy=5.0,
        context='GITHUB_TOKEN=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',
        confidence=0.9,
    )

    # Add candidates
    finding1, is_new1 = dedup.add_or_merge(candidate1)
    print(f"\nAdded candidate 1: new={is_new1}, sources={len(finding1.sources)}")

    finding2, is_new2 = dedup.add_or_merge(candidate2)
    print(f"Added candidate 2 (duplicate): new={is_new2}, sources={len(finding2.sources)}")

    finding3, is_new3 = dedup.add_or_merge(candidate3)
    print(f"Added candidate 3 (duplicate): new={is_new3}, sources={len(finding3.sources)}")

    finding4, is_new4 = dedup.add_or_merge(candidate4)
    print(f"Added candidate 4 (different): new={is_new4}, sources={len(finding4.sources)}")

    # Check stats
    stats = dedup.get_stats()
    print(f"\nDeduplication Stats:")
    print(f"  Unique findings: {stats['unique_findings']}")
    print(f"  Total sources: {stats['total_sources']}")
    print(f"  Multi-source findings: {stats['multi_source_findings']}")
    print(f"  Avg sources per finding: {stats['avg_sources_per_finding']:.2f}")

    # Check confidence boost
    aws_finding = dedup.get_finding('AKIAIOSFODNN7EXAMPLE', 'aws_access_key')
    print(f"\nAWS Key confidence after 3 sources: {aws_finding.confidence:.2f}")
    print(f"Confidence factors: {aws_finding.confidence_factors}")

    print()


def test_pairing():
    """Test credential pairing."""
    print("=" * 70)
    print("TEST: Credential Pairing")
    print("=" * 70)

    pairer = CredentialPairer()

    source = Source(type='url', url='https://example.com/config.js')

    # Shared context (both credentials appear together)
    shared_context = """
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    """

    # AWS access key and secret (should pair)
    aws_key = Candidate(
        type='aws_access_key',
        value='AKIAIOSFODNN7EXAMPLE',
        source=source,
        entropy=4.5,
        context=shared_context,
        confidence=0.8,
    )

    aws_secret = Candidate(
        type='aws_secret_key',
        value='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        source=source,
        entropy=5.2,
        context=shared_context,
        confidence=0.8,
    )

    # GitHub token (no pair)
    github_token = Candidate(
        type='github_token',
        value='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',
        source=source,
        entropy=5.0,
        context='token: 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',
        confidence=0.9,
    )

    # Add candidates
    pairer.add_candidate(aws_key)
    pairer.add_candidate(aws_secret)
    pairer.add_candidate(github_token)

    # Find pairs
    pairs = pairer.find_pairs()

    print(f"\nFound {len(pairs)} credential pairs:")
    for cand1, cand2 in pairs:
        print(f"\nPair:")
        print(f"  {cand1.type}: {cand1.value[:30]}...")
        print(f"  {cand2.type}: {cand2.value[:30]}...")
        print(f"  Same source: {cand1.source.url == cand2.source.url}")

    print()


def test_confidence_scoring():
    """Test multi-factor confidence scoring."""
    print("=" * 70)
    print("TEST: Confidence Scoring")
    print("=" * 70)

    scorer = ConfidenceScorer()

    # Create findings with different characteristics
    source1 = Source(type='url', url='https://example.com/config.js')
    source2 = Source(type='url', url='https://example.com/env.js')
    source3 = Source(type='url', url='https://api.example.com/secrets')

    # High-value, multi-source finding
    from xposure.core.models import Finding

    finding1 = Finding(
        id='test1',
        credential_type='aws_access_key',
        value='AKIAIOSFODNN7EXAMPLE',
        masked_value='AKIAIOSF••••••••••••••',
        sources=[source1, source2, source3],  # 3 sources
        confidence=0.8,
        severity=Severity.CRITICAL,
        entropy=4.8,
        metadata={'provider': 'aws'},
    )

    # Low-value, single-source finding
    finding2 = Finding(
        id='test2',
        credential_type='telegram_bot',
        value='1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ1234567',
        masked_value='1234567890••••••••••••••••••••••••••',
        sources=[source1],  # 1 source
        confidence=0.6,
        severity=Severity.MEDIUM,
        entropy=4.2,
        metadata={'provider': 'telegram'},
    )

    # Score findings
    score1 = scorer.calculate_score(finding1, is_paired=True, context_quality=0.8)
    score2 = scorer.calculate_score(finding2, is_paired=False, context_quality=0.5)

    print(f"\nFinding 1 (AWS key, multi-source, paired):")
    print(f"  Base confidence: {finding1.confidence:.2f}")
    print(f"  Final score: {score1:.2f}")
    print(f"  Level: {scorer.get_confidence_level(score1)}")

    print(f"\nFinding 2 (Telegram, single-source):")
    print(f"  Base confidence: {finding2.confidence:.2f}")
    print(f"  Final score: {score2:.2f}")
    print(f"  Level: {scorer.get_confidence_level(score2)}")

    # Test context analysis
    sample_content = """
    const config = {
        AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE",
        AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    };
    """

    context_quality = scorer.analyze_context_quality(
        content=sample_content,
        position=sample_content.find('AKIAIOSFODNN7EXAMPLE'),
        value='AKIAIOSFODNN7EXAMPLE',
    )

    print(f"\nContext quality for AWS key: {context_quality:.2f}")

    # Stats
    stats = scorer.get_stats()
    print(f"\nScoring Stats:")
    print(f"  Total scored: {stats['total_scored']}")
    print(f"  Avg score: {stats['avg_score']:.2f}")
    print(f"  High confidence: {stats['high_confidence']}")
    print(f"  Low confidence: {stats['low_confidence']}")

    print()


def test_content_graph():
    """Test content relationship graph."""
    print("=" * 70)
    print("TEST: Content Graph")
    print("=" * 70)

    graph = ContentGraph()

    # Create sources
    root_domain = Source(type='domain', url='https://example.com')
    subdomain = Source(type='subdomain', url='https://api.example.com')
    js_file = Source(type='js_file', url='https://api.example.com/bundle.js')

    # Track discoveries
    graph.track_discovery(
        source=root_domain,
        discovered_url='https://api.example.com',
        discovered_type='subdomain',
    )

    graph.track_discovery(
        source=subdomain,
        discovered_url='https://api.example.com/bundle.js',
        discovered_type='js_file',
    )

    # Create findings
    from xposure.core.models import Finding

    finding1 = Finding(
        id='finding1',
        credential_type='aws_access_key',
        value='AKIAIOSFODNN7EXAMPLE',
        masked_value='AKIAIOSF••••••••••••••',
        sources=[js_file],
        confidence=0.8,
        severity=Severity.CRITICAL,
    )

    finding2 = Finding(
        id='finding2',
        credential_type='aws_secret_key',
        value='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        masked_value='wJalrXUt••••••••••••••••••••••••••',
        sources=[js_file],
        confidence=0.8,
        severity=Severity.CRITICAL,
    )

    # Track findings
    graph.track_finding(finding1)
    graph.track_finding(finding2)

    # Link pair
    graph.link_pair(finding1, finding2)

    # Get evidence chain
    chain = graph.get_evidence_chain('finding1')
    print(f"\nEvidence chain for finding1:")
    for i, node in enumerate(chain):
        print(f"  {i}. [{node.type}] {node.url or node.id}")

    # Get related findings
    related = graph.get_related_findings('finding1', max_depth=2)
    print(f"\nRelated findings to finding1: {related}")

    # Get paired findings
    paired = graph.get_paired_findings('finding1')
    print(f"Paired with finding1: {paired}")

    # Stats
    stats = graph.get_stats()
    print(f"\nGraph Stats:")
    print(f"  Total nodes: {stats['total_nodes']}")
    print(f"  Total edges: {stats['total_edges']}")
    print(f"  Node types: {stats['node_types']}")
    print(f"  Edge types: {stats['edge_types']}")
    print(f"  Avg node degree: {stats['avg_node_degree']:.2f}")

    print()


def test_full_correlation_pipeline():
    """Test full correlation pipeline."""
    print("=" * 70)
    print("TEST: Full Correlation Pipeline")
    print("=" * 70)

    # Initialize components
    dedup = Deduplicator()
    pairer = CredentialPairer()
    scorer = ConfidenceScorer()
    graph = ContentGraph()

    # Create test candidates
    source1 = Source(type='url', url='https://example.com/config.js')
    source2 = Source(type='url', url='https://example.com/env.js')

    # Shared AWS context
    aws_context = """
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    """

    candidates = [
        # AWS pair from source1
        Candidate(
            type='aws_access_key',
            value='AKIAIOSFODNN7EXAMPLE',
            source=source1,
            entropy=4.5,
            context=aws_context,
            confidence=0.8,
        ),
        Candidate(
            type='aws_secret_key',
            value='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            source=source1,
            entropy=5.2,
            context=aws_context,
            confidence=0.8,
        ),
        # Same AWS key from source2 (duplicate)
        Candidate(
            type='aws_access_key',
            value='AKIAIOSFODNN7EXAMPLE',
            source=source2,
            entropy=4.5,
            context='AWS_KEY: AKIAIOSFODNN7EXAMPLE',
            confidence=0.8,
        ),
        # GitHub token
        Candidate(
            type='github_token',
            value='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',
            source=source1,
            entropy=5.0,
            context='token=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',
            confidence=0.9,
        ),
        # OpenAI key
        Candidate(
            type='openai_key',
            value='sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz',
            source=source2,
            entropy=4.8,
            context='OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz',
            confidence=0.85,
        ),
    ]

    print(f"\nProcessing {len(candidates)} candidates...")

    # 1. Deduplication
    findings = []
    for candidate in candidates:
        finding, is_new = dedup.add_or_merge(candidate)
        if is_new:
            findings.append(finding)

    print(f"After dedup: {len(findings)} unique findings")

    # 2. Pairing
    for candidate in candidates:
        pairer.add_candidate(candidate)

    pairs = pairer.find_pairs()
    print(f"Found {len(pairs)} credential pairs")

    paired_finding_ids = set()
    for cand1, cand2 in pairs:
        finding1 = dedup.get_finding(cand1.value, cand1.type)
        finding2 = dedup.get_finding(cand2.value, cand2.type)
        if finding1 and finding2:
            graph.link_pair(finding1, finding2)
            paired_finding_ids.add(finding1.id)
            paired_finding_ids.add(finding2.id)

    # 3. Confidence scoring
    for finding in findings:
        is_paired = finding.id in paired_finding_ids
        final_score = scorer.calculate_score(
            finding=finding,
            is_paired=is_paired,
            context_quality=0.7,
        )
        finding.confidence = final_score

    # 4. Track in graph
    for finding in findings:
        graph.track_finding(finding)

    # Display results
    print(f"\n{'='*70}")
    print("FINAL FINDINGS")
    print('='*70)

    for finding in sorted(findings, key=lambda f: f.confidence, reverse=True):
        is_paired = finding.id in paired_finding_ids
        level = scorer.get_confidence_level(finding.confidence)

        print(f"\n[{finding.credential_type}]")
        print(f"  Value: {finding.masked_value}")
        print(f"  Sources: {len(finding.sources)}")
        print(f"  Confidence: {finding.confidence:.2f} ({level})")
        print(f"  Severity: {finding.severity.value if finding.severity else 'N/A'}")
        print(f"  Paired: {is_paired}")

    print()


if __name__ == '__main__':
    test_deduplication()
    test_pairing()
    test_confidence_scoring()
    test_content_graph()
    test_full_correlation_pipeline()

    print("=" * 70)
    print("All correlation tests completed!")
    print("=" * 70)
