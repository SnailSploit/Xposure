"""Verification module for X-POSURE."""

from .base import BaseVerifier, PassiveVerifier, VerificationResult
from .coordinator import VerifierCoordinator, verify_finding
from .aws import AWSVerifier
from .github import GitHubVerifier
from .slack import SlackVerifier
from .stripe import StripeVerifier
from .openai import OpenAIVerifier

__all__ = [
    'BaseVerifier',
    'PassiveVerifier',
    'VerificationResult',
    'VerifierCoordinator',
    'verify_finding',
    'AWSVerifier',
    'GitHubVerifier',
    'SlackVerifier',
    'StripeVerifier',
    'OpenAIVerifier',
]
