"""Verification module for X-POSURE."""

from .base import BaseVerifier, PassiveVerifier, VerificationResult
from .coordinator import VerifierCoordinator, verify_finding
from .aws import AWSVerifier
from .github import GitHubVerifier
from .slack import SlackVerifier
from .stripe import StripeVerifier
from .openai import OpenAIVerifier
from .gcp import GCPVerifier
from .azure import AzureVerifier
from .jwt import JWTVerifier
from .shodan import ShodanVerifier
from .sendgrid import SendGridVerifier
from .twilio import TwilioVerifier
from .discord import DiscordVerifier
from .telegram import TelegramVerifier
from .heroku import HerokuVerifier
from .digitalocean import DigitalOceanVerifier
from .mongodb import MongoDBVerifier
from .postgres import PostgresVerifier
from .redis_verify import RedisVerifier
from .npm import NPMVerifier
from .pypi import PyPIVerifier
from .anthropic import AnthropicVerifier
from .cloudflare import CloudflareVerifier
from .vault import VaultVerifier
from .supabase import SupabaseVerifier

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
    'GCPVerifier',
    'AzureVerifier',
    'JWTVerifier',
    'ShodanVerifier',
    'SendGridVerifier',
    'TwilioVerifier',
    'DiscordVerifier',
    'TelegramVerifier',
    'HerokuVerifier',
    'DigitalOceanVerifier',
    'MongoDBVerifier',
    'PostgresVerifier',
    'RedisVerifier',
    'NPMVerifier',
    'PyPIVerifier',
    'AnthropicVerifier',
    'CloudflareVerifier',
    'VaultVerifier',
    'SupabaseVerifier',
]
