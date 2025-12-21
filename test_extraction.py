#!/usr/bin/env python3
"""Test extraction modules."""

from xposure.extract.quick import QuickScanner
from xposure.extract.decode import DecodeChain
from xposure.extract.ast import JSASTParser
from xposure.extract.objects import ObjectExtractor
from xposure.core.models import Source


def test_quick_scan():
    """Test quick scanning."""
    print("=" * 70)
    print("TEST: Quick Scan")
    print("=" * 70)

    sample_content = """
    const API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz";
    const GITHUB_TOKEN = "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";
    const SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX";
    const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
    const password = "super_secret_password_123";
    """

    source = Source(type='test', url='test://sample')
    scanner = QuickScanner()

    candidates = list(scanner.scan(sample_content, source))

    print(f"\nFound {len(candidates)} candidates:\n")
    for candidate in candidates:
        print(f"  [{candidate.type}] {candidate.value[:40]}... (entropy: {candidate.entropy:.2f})")

    print()


def test_decode_chain():
    """Test decode chain."""
    print("=" * 70)
    print("TEST: Decode Chain")
    print("=" * 70)

    # Base64 encoded "secret_key=my_api_key_12345"
    encoded = "c2VjcmV0X2tleT1teV9hcGlfa2V5XzEyMzQ1"

    decoder = DecodeChain(max_depth=3)

    print(f"\nOriginal: {encoded}")
    print("\nDecoded variants:")

    for decoded, path in decoder.decode_all(encoded):
        if path:
            print(f"  [{' -> '.join(path)}]: {decoded}")

    print()


def test_ast_parser():
    """Test AST parser."""
    print("=" * 70)
    print("TEST: JavaScript AST Parser")
    print("=" * 70)

    js_code = """
    const apiKey = "sk_test_1234567890";
    const config = {
        apiSecret: "secret_abc123",
        endpoint: "https://api.example.com"
    };
    var token = "bearer_token_xyz";
    """

    parser = JSASTParser()

    print("\nExtracted assignments:")

    for assignment in parser.extract_assignments(js_code):
        print(f"  {assignment['type']} {assignment['name']} = {assignment['value']}")

    print()


def test_object_extractor():
    """Test object extraction."""
    print("=" * 70)
    print("TEST: Object Extractor")
    print("=" * 70)

    sample_content = """
    {
        "api_key": "sk_live_abcdef123456",
        "api_secret": "secret_xyz789",
        "database_url": "postgres://user:pass@localhost/db"
    }

    mongodb://admin:password123@mongodb.example.com:27017/mydb

    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    """

    extractor = ObjectExtractor()

    print("\nJSON Objects:")
    for obj in extractor.extract_json_objects(sample_content):
        print(f"  {obj['value']}")

    print("\nConnection Strings:")
    for conn in extractor.extract_connection_strings(sample_content):
        print(f"  [{conn['db_type']}] {conn['uri']}")
        print(f"    user: {conn['username']}, pass: {conn['password']}")

    print("\nKey-Value Pairs:")
    for kv in extractor.extract_key_value_pairs(sample_content):
        print(f"  {kv['key']} = {kv['value']}")

    print("\nCredential Pairs:")
    for pair in extractor.extract_credential_pairs(sample_content):
        print(f"  {pair['key_name']} + {pair['secret_name']} (proximity: {pair['proximity']})")

    print()


if __name__ == '__main__':
    test_quick_scan()
    test_decode_chain()
    test_ast_parser()
    test_object_extractor()

    print("=" * 70)
    print("All tests completed!")
    print("=" * 70)
