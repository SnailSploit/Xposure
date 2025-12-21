#!/usr/bin/env python3
"""Test rules engine."""

from xposure.rules.engine import RuleEngine
from xposure.core.models import Source


def test_rules_loading():
    """Test loading rules."""
    print("=" * 70)
    print("TEST: Rules Loading")
    print("=" * 70)

    engine = RuleEngine()

    stats = engine.get_stats()

    print(f"\nLoaded {stats['total_rules']} rules")
    print(f"\nRules by type ({len(stats['rule_types'])} types):")
    for rule_type, count in sorted(stats['rule_types'].items()):
        print(f"  {rule_type}: {count}")

    print(f"\nRules by severity:")
    for severity, count in sorted(stats['severities'].items()):
        print(f"  {severity}: {count}")

    print()


def test_rule_matching():
    """Test rule matching."""
    print("=" * 70)
    print("TEST: Rule Matching")
    print("=" * 70)

    sample_content = """
    const config = {
        openaiKey: "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz",
        githubToken: "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",
        slackWebhook: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX",
        awsAccessKey: "AKIAIOSFODNN7EXAMPLE",
        awsSecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        stripeKey: "sk_live_abcdef123456789",
        mongoUri: "mongodb://admin:password123@mongodb.example.com:27017/mydb"
    };
    """

    source = Source(type='test', url='test://sample')
    engine = RuleEngine()

    candidates = list(engine.scan(sample_content, source))

    print(f"\nFound {len(candidates)} candidates:\n")
    for candidate in candidates:
        print(f"  [{candidate.type}] {candidate.value[:40]}...")
        print(f"    Severity: {getattr(candidate, 'severity', 'N/A')}")
        print(f"    Confidence: {candidate.confidence:.2f}")
        print(f"    Entropy: {candidate.entropy:.2f}")
        print()


def test_context_matching():
    """Test context-based matching."""
    print("=" * 70)
    print("TEST: Context-Based Matching")
    print("=" * 70)

    # This should NOT match (no context)
    no_context = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    # This SHOULD match (has AWS context)
    with_context = """
    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    """

    source = Source(type='test', url='test://context')
    engine = RuleEngine()

    print("\nScanning without context:")
    candidates_no_ctx = list(engine.scan(no_context, source))
    print(f"  Found {len(candidates_no_ctx)} candidates")

    print("\nScanning with context:")
    candidates_with_ctx = list(engine.scan(with_context, source))
    print(f"  Found {len(candidates_with_ctx)} candidates")

    for candidate in candidates_with_ctx:
        print(f"  - {candidate.type}: {candidate.value[:40]}...")

    print()


def test_pairing():
    """Test credential pairing."""
    print("=" * 70)
    print("TEST: Credential Pairing")
    print("=" * 70)

    sample_content = """
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    """

    source = Source(type='test', url='test://pairing')
    engine = RuleEngine()

    candidates = list(engine.scan(sample_content, source))

    print(f"\nFound {len(candidates)} candidates:")
    for candidate in candidates:
        print(f"\n  [{candidate.type}]")
        print(f"    Value: {candidate.value[:40]}...")

        # Get paired rules
        paired_rules = engine.get_paired_rules(candidate.type)
        if paired_rules:
            print(f"    Should pair with: {[r.type for r in paired_rules]}")

    print()


if __name__ == '__main__':
    test_rules_loading()
    test_rule_matching()
    test_context_matching()
    test_pairing()

    print("=" * 70)
    print("All rules tests completed!")
    print("=" * 70)
