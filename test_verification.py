#!/usr/bin/env python3
"""Test verification module."""

import asyncio
from xposure.verify.base import PassiveVerifier
from xposure.verify.coordinator import VerifierCoordinator
from xposure.core.models import Finding, Source, Severity


def test_passive_verification():
    """Test passive verification for various credential types."""
    print("=" * 70)
    print("TEST: Passive Verification")
    print("=" * 70)

    passive = PassiveVerifier()

    test_cases = [
        # AWS Access Key (valid format)
        Finding(
            id='test1',
            credential_type='aws_access_key',
            value='AKIAIOSFODNN7EXAMPLE',
            masked_value='AKIAIOSF••••••••••••',
            sources=[Source(type='url', url='https://example.com')],
        ),
        # GitHub Token (valid format)
        Finding(
            id='test2',
            credential_type='github_token',
            value='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',
            masked_value='ghp_wWPw••••••••••••••••••••••••••••••••',
            sources=[Source(type='url', url='https://example.com')],
        ),
        # Stripe Live Secret Key
        Finding(
            id='test3',
            credential_type='stripe_secret_key',
            value='sk_live_TESTKEY_NOT_REAL_JUST_EXAMPLE_STRING',
            masked_value='sk_live_••••••••••••••••••••••••••••••••',
            sources=[Source(type='url', url='https://example.com')],
        ),
        # Stripe Test Key
        Finding(
            id='test4',
            credential_type='stripe_secret_key',
            value='sk_test_TESTKEY_NOT_REAL_JUST_EXAMPLE_STRING',
            masked_value='sk_test_••••••••••••••••••••••••••••••••',
            sources=[Source(type='url', url='https://example.com')],
        ),
        # OpenAI Key (project)
        Finding(
            id='test5',
            credential_type='openai_key',
            value='sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz',
            masked_value='sk-proj-••••••••••••••••••••••••••••••••••••••••••••••••••',
            sources=[Source(type='url', url='https://example.com')],
        ),
        # Invalid AWS key (wrong length)
        Finding(
            id='test6',
            credential_type='aws_access_key',
            value='AKIAINVALIDKEY',
            masked_value='AKIAINVA••••••••',
            sources=[Source(type='url', url='https://example.com')],
        ),
    ]

    for finding in test_cases:
        result = passive.passive_verify(finding)

        print(f"\n[{finding.credential_type}] {finding.value[:30]}...")
        print(f"  Status: {result.status.value}")
        print(f"  Method: {result.method}")
        print(f"  Environment: {result.environment or 'N/A'}")
        print(f"  Metadata: {result.metadata}")


def test_verifier_routing():
    """Test verifier routing logic."""
    print("\n" + "=" * 70)
    print("TEST: Verifier Routing")
    print("=" * 70)

    coordinator = VerifierCoordinator(passive_only=True)

    # Test which verifiers support which types
    test_types = [
        'aws_access_key',
        'github_token',
        'slack_token',
        'stripe_secret_key',
        'openai_key',
        'unknown_type',
    ]

    print(f"\nSupported credential types by verifiers:")
    for cred_type in test_types:
        finding = Finding(
            id='test',
            credential_type=cred_type,
            value='test_value',
            masked_value='test••••',
            sources=[],
        )

        verifier = coordinator._get_verifier(finding)
        verifier_name = verifier.__class__.__name__ if verifier else 'None'

        print(f"  {cred_type:30} -> {verifier_name}")

    print(f"\nAll supported types: {coordinator.get_supported_types()}")


async def _async_verification_structure():
    """Async portion of verification structure test."""
    print("\n" + "=" * 70)
    print("TEST: Verification Structure")
    print("=" * 70)

    # Create sample findings
    findings = [
        Finding(
            id='aws1',
            credential_type='aws_access_key',
            value='AKIAIOSFODNN7EXAMPLE',
            masked_value='AKIAIOSF••••••••••••',
            sources=[Source(type='url', url='https://example.com/config.js')],
            confidence=0.85,
            entropy=4.5,
            metadata={'provider': 'aws'},
            severity=Severity.CRITICAL,
        ),
        Finding(
            id='github1',
            credential_type='github_token',
            value='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',
            masked_value='ghp_wWPw••••••••••••••••••••••••••••••••',
            sources=[Source(type='url', url='https://example.com/env.js')],
            confidence=0.92,
            entropy=5.0,
            metadata={'provider': 'github'},
            severity=Severity.HIGH,
        ),
        Finding(
            id='stripe1',
            credential_type='stripe_secret_key',
            value='sk_live_TESTKEY_NOT_REAL_JUST_EXAMPLE_STRING',
            masked_value='sk_live_••••••••••••••••••••••••••••••••',
            sources=[Source(type='url', url='https://example.com/checkout.js')],
            confidence=0.88,
            entropy=4.8,
            metadata={'provider': 'stripe'},
            severity=Severity.CRITICAL,
        ),
    ]

    # Verify with passive-only coordinator
    coordinator = VerifierCoordinator(passive_only=True, max_concurrent=3)

    print(f"\nVerifying {len(findings)} findings (passive mode)...")

    verified_results = await coordinator.verify_findings(findings)

    print(f"\nVerification Results:")
    for finding, result in verified_results:
        print(f"\n[{finding.credential_type}] {finding.masked_value}")
        print(f"  ID: {finding.id}")
        print(f"  Status: {result.status.value}")
        print(f"  Method: {result.method}")
        print(f"  Environment: {result.environment or 'Unknown'}")
        if result.identity:
            print(f"  Identity: {result.identity}")
        if result.permissions:
            print(f"  Permissions: {', '.join(result.permissions[:3])}")
        if result.blast_radius:
            print(f"  Blast Radius: {result.blast_radius.value}")
        if result.metadata:
            print(f"  Metadata: {result.metadata}")

    # Show stats
    stats = coordinator.get_stats()
    print(f"\nVerification Statistics:")
    print(f"  Total verified: {stats['total_verified']}")
    print(f"  Verified: {stats['verified']}")
    print(f"  Invalid: {stats['invalid']}")
    print(f"  Errors: {stats['errors']}")
    print(f"  Unverified: {stats['unverified']}")


async def _async_aws_signature():
    """Async portion of AWS signature generation test."""
    print("\n" + "=" * 70)
    print("TEST: AWS Signature Structure")
    print("=" * 70)

    from xposure.verify.aws import AWSVerifier

    verifier = AWSVerifier()

    # Generate signature headers (won't work without real creds)
    headers = verifier._sign_request(
        method='POST',
        host='sts.us-east-1.amazonaws.com',
        uri='/',
        params={'Action': 'GetCallerIdentity', 'Version': '2011-06-15'},
        access_key='AKIAIOSFODNN7EXAMPLE',
        secret_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        region='us-east-1',
        service='sts',
    )

    print("\nAWS Signature V4 Headers generated:")
    for key, value in headers.items():
        print(f"  {key}: {value[:80]}{'...' if len(value) > 80 else ''}")


def test_github_token_types():
    """Test GitHub token type detection."""
    print("\n" + "=" * 70)
    print("TEST: GitHub Token Type Detection")
    print("=" * 70)

    from xposure.verify.base import PassiveVerifier

    passive = PassiveVerifier()

    github_tokens = [
        ('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', 'Personal Access Token'),
        ('gho_16C7e42F292c6912E7710c838347Ae178B4a', 'OAuth Access Token'),
        ('ghu_16C7e42F292c6912E7710c838347Ae178B4a', 'User-to-Server Token'),
        ('ghs_16C7e42F292c6912E7710c838347Ae178B4a', 'Server-to-Server Token'),
        ('ghr_1B4a2e77838347Ae178B4a6C7e42F292c691', 'Refresh Token'),
    ]

    print("\nGitHub Token Types:")
    for token, expected_type in github_tokens:
        token_type = passive._get_github_token_type(token)
        prefix = token[:4]
        match = "✓" if token_type == expected_type else "✗"

        print(f"  {match} {prefix}... -> {token_type}")


def test_verification_structure():
    """Test verification structure with sample findings."""
    asyncio.run(_async_verification_structure())


def test_aws_signature():
    """Test AWS signature generation (structure only)."""
    asyncio.run(_async_aws_signature())


def main():
    """Run all tests."""
    test_passive_verification()
    test_verifier_routing()
    test_verification_structure()
    test_aws_signature()
    test_github_token_types()

    print("\n" + "=" * 70)
    print("All verification tests completed!")
    print("=" * 70)
    print("\nNote: Active verification tests require real credentials.")
    print("Passive verification demonstrates format checking and validation.")


if __name__ == '__main__':
    main()
