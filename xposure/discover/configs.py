"""Configuration file discovery for X-POSURE."""

from typing import AsyncGenerator
from urllib.parse import urljoin

from .base import BaseDiscoverer


class ConfigDiscoverer(BaseDiscoverer):
    """Discover exposed configuration files."""

    # Common config file paths that often contain secrets
    CONFIG_PATHS = [
        # Environment files
        '/.env',
        '/.env.local',
        '/.env.development',
        '/.env.production',
        '/.env.staging',
        '/.env.backup',
        '/.env.old',
        '/.env.example',  # Sometimes contains real values
        '/env.js',
        '/env.json',
        
        # JavaScript/Node configs
        '/config.js',
        '/config.json',
        '/config.yaml',
        '/config.yml',
        '/settings.js',
        '/settings.json',
        '/app.config.js',
        '/app.config.json',
        '/next.config.js',
        '/nuxt.config.js',
        '/vue.config.js',
        '/angular.json',
        '/.npmrc',
        '/package.json',  # Sometimes has scripts with secrets
        
        # Python configs
        '/settings.py',
        '/config.py',
        '/local_settings.py',
        '/.pypirc',
        '/pytest.ini',
        '/setup.cfg',
        
        # PHP configs
        '/wp-config.php',
        '/wp-config.php.bak',
        '/wp-config.php.old',
        '/configuration.php',
        '/config.php',
        '/settings.php',
        '/database.php',
        '/.htpasswd',
        
        # Java/.NET configs
        '/application.properties',
        '/application.yml',
        '/application.yaml',
        '/appsettings.json',
        '/appsettings.Development.json',
        '/appsettings.Production.json',
        '/web.config',
        '/Web.config',
        
        # Ruby configs
        '/config/database.yml',
        '/config/secrets.yml',
        '/config/master.key',
        '/config/credentials.yml.enc',
        '/.ruby-version',
        
        # Cloud provider configs
        '/.aws/credentials',
        '/.aws/config',
        '/.gcloud/credentials.json',
        '/google-credentials.json',
        '/service-account.json',
        '/firebase.json',
        '/firebaseConfig.js',
        '/.digitalocean/config.yaml',
        
        # Docker/K8s
        '/docker-compose.yml',
        '/docker-compose.yaml',
        '/docker-compose.override.yml',
        '/Dockerfile',
        '/.docker/config.json',
        '/kubernetes.yaml',
        '/k8s.yaml',
        '/helm/values.yaml',
        
        # CI/CD
        '/.travis.yml',
        '/.gitlab-ci.yml',
        '/.github/workflows/main.yml',
        '/Jenkinsfile',
        '/bitbucket-pipelines.yml',
        '/azure-pipelines.yml',
        '/cloudbuild.yaml',
        
        # Git
        '/.git/config',
        '/.gitconfig',
        
        # Database
        '/database.yml',
        '/db.json',
        '/db.sqlite',
        '/dump.sql',
        '/backup.sql',
        
        # SSL/Keys
        '/server.key',
        '/server.pem',
        '/private.key',
        '/id_rsa',
        '/id_rsa.pub',
        '/.ssh/id_rsa',
        '/.ssh/authorized_keys',
        
        # Misc
        '/secrets.json',
        '/secrets.yaml',
        '/credentials.json',
        '/auth.json',
        '/apikeys.json',
        '/Thumbs.db',  # Windows metadata, can leak paths
        '/desktop.ini',
        '/.DS_Store',  # macOS metadata
        '/debug.log',
        '/error.log',
        '/access.log',
        '/npm-debug.log',
        '/yarn-error.log',
        
        # Backups
        '/backup.zip',
        '/backup.tar.gz',
        '/site.zip',
        '/www.zip',
        '/html.zip',
        '/db.zip',
    ]

    # Paths to check on discovered subdomains
    SUBDOMAIN_PATHS = [
        '/.env',
        '/config.json',
        '/api/config',
        '/api/settings',
        '/api/v1/config',
        '/.git/config',
        '/debug',
        '/status',
        '/health',
        '/info',
        '/swagger.json',
        '/openapi.json',
        '/api-docs',
        '/graphql',  # GraphQL introspection
    ]

    async def discover(self, subdomains: list[str] = None) -> AsyncGenerator[dict, None]:
        """
        Discover configuration files.

        Args:
            subdomains: List of discovered subdomains to check

        Yields:
            dict: Result with type='config', url, content, metadata
        """
        base_urls = [f"https://{self.config.target}", f"https://www.{self.config.target}"]
        
        # Add subdomains
        if subdomains:
            for sub in subdomains[:20]:  # Limit subdomain checks
                if sub.startswith('http'):
                    base_urls.append(sub)
                else:
                    base_urls.append(f"https://{sub}")

        # Check main domain with all paths
        for base_url in base_urls[:2]:  # Main domain + www
            for path in self.CONFIG_PATHS:
                async for result in self._check_config(base_url, path):
                    yield result

        # Check subdomains with limited paths
        for base_url in base_urls[2:]:
            for path in self.SUBDOMAIN_PATHS:
                async for result in self._check_config(base_url, path):
                    yield result

    async def _check_config(self, base_url: str, path: str) -> AsyncGenerator[dict, None]:
        """
        Check if a config file exists and is accessible.

        Args:
            base_url: Base URL to check
            path: Config path to append

        Yields:
            Config file results
        """
        url = urljoin(base_url, path)
        
        content = await self.fetch(url)
        
        if not content:
            return
            
        # Skip error pages and redirects
        if self._is_error_page(content):
            return

        # Determine file type
        file_type = self._detect_file_type(path, content)
        
        # Calculate interest score
        interest_score = self._calculate_interest(content, path)
        
        if interest_score < 0.3:
            return

        yield {
            'type': 'config_file',
            'url': url,
            'content': content,
            'metadata': {
                'path': path,
                'file_type': file_type,
                'interest_score': interest_score,
                'size': len(content),
            }
        }

    def _is_error_page(self, content: str) -> bool:
        """Check if content is an error page."""
        error_indicators = [
            '<title>404',
            '<title>403',
            '<title>Not Found',
            '<title>Access Denied',
            '<title>Error',
            'Page not found',
            'File not found',
            'The requested URL was not found',
            'nginx error',
            'Apache error',
        ]
        
        content_lower = content[:2000].lower()
        return any(ind.lower() in content_lower for ind in error_indicators)

    def _detect_file_type(self, path: str, content: str) -> str:
        """Detect the type of config file."""
        path_lower = path.lower()
        
        if path_lower.endswith(('.json',)):
            return 'json'
        elif path_lower.endswith(('.yaml', '.yml')):
            return 'yaml'
        elif path_lower.endswith(('.js',)):
            return 'javascript'
        elif path_lower.endswith(('.php',)):
            return 'php'
        elif path_lower.endswith(('.py',)):
            return 'python'
        elif path_lower.endswith(('.xml',)):
            return 'xml'
        elif path_lower.endswith(('.env',)) or '.env' in path_lower:
            return 'dotenv'
        elif path_lower.endswith(('.sql',)):
            return 'sql'
        elif path_lower.endswith(('.key', '.pem')):
            return 'key'
        
        # Detect by content
        content_start = content[:100].strip()
        if content_start.startswith('{'):
            return 'json'
        elif content_start.startswith('<?php'):
            return 'php'
        elif content_start.startswith('---') or ': ' in content_start:
            return 'yaml'
        elif '=' in content_start and not '<' in content_start:
            return 'dotenv'
        elif content_start.startswith('-----BEGIN'):
            return 'key'
        
        return 'unknown'

    def _calculate_interest(self, content: str, path: str) -> float:
        """
        Calculate how interesting a config file is.
        
        Returns:
            Score from 0.0 to 1.0
        """
        score = 0.3  # Base score for any accessible config
        
        # High-value file types
        high_value_paths = ['.env', 'credentials', 'secrets', 'apikey', 'private', '.key', '.pem']
        if any(hv in path.lower() for hv in high_value_paths):
            score += 0.3
        
        # Content indicators
        secret_indicators = [
            'password', 'passwd', 'pwd',
            'secret', 'token', 'api_key', 'apikey',
            'access_key', 'private_key', 'auth',
            'credential', 'connection_string',
            'database_url', 'db_pass', 'db_password',
            'smtp_pass', 'mail_password',
            'aws_', 'azure_', 'gcp_', 'google_',
            'stripe_', 'twilio_', 'sendgrid_',
            'BEGIN RSA', 'BEGIN PRIVATE', 'BEGIN CERTIFICATE',
            'mongodb://', 'postgres://', 'mysql://',
            'redis://', 'amqp://',
        ]
        
        content_lower = content.lower()
        matches = sum(1 for ind in secret_indicators if ind.lower() in content_lower)
        score += min(0.4, matches * 0.05)
        
        # Penalty for looking like documentation
        if 'example' in content_lower and 'your_' in content_lower:
            score -= 0.2
        if '# ' in content[:500] and content.count('#') > 10:
            score -= 0.1  # Likely heavily commented example
            
        return max(0.0, min(1.0, score))
