# X-POSURE v4.0

```

    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
    █                                                                        █
    █  ██╗  ██╗      ██████╗  ██████╗ ███████╗██╗   ██╗██████╗ ███████╗      █
    █  ╚██╗██╔╝      ██╔══██╗██╔═══██╗██╔════╝██║   ██║██╔══██╗██╔════╝      █
    █   ╚███╔╝ █████╗██████╔╝██║   ██║███████╗██║   ██║██████╔╝█████╗        █
    █   ██╔██╗ ╚════╝██╔═══╝ ██║   ██║╚════██║██║   ██║██╔══██╗██╔══╝        █
    █  ██╔╝ ██╗      ██║     ╚██████╔╝███████║╚██████╔╝██║  ██║███████╗      █
    █  ╚═╝  ╚═╝      ╚═╝      ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝      █
    █                                                                        █
    █  [ v4.0.0 ]  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  [ ENTERPRISE ]       █
    █                                                                        █
    █  "Control is an illusion. But credentials? Those are real."            █
    █                                                    - Mr. Robot, maybe  █
    █                                                                        █
    ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀

                    [ The shit your DevOps forgot. ]
                              by SnailSploit
```

<p align="center">
  <img src="https://img.shields.io/badge/version-4.0.0-ff0040?style=for-the-badge&labelColor=1a1a2e" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10+-00d4ff?style=for-the-badge&labelColor=1a1a2e" alt="Python">
  <img src="https://img.shields.io/badge/status-OPERATIONAL-00ff41?style=for-the-badge&labelColor=1a1a2e" alt="Status">
  <img src="https://img.shields.io/badge/license-MIT-9d4edd?style=for-the-badge&labelColor=1a1a2e" alt="License">
</p>

<p align="center">
  <code>[ AUTONOMOUS CREDENTIAL HARVESTING SYSTEM ]</code>
</p>

---

## `> whoami`

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│  X-POSURE is not just another scanner.                                      │
│                                                                              │
│  It's a fully autonomous credential intelligence platform that discovers,   │
│  extracts, correlates, verifies, and reports exposed secrets across your    │
│  target's entire attack surface.                                            │
│                                                                              │
│  Built for those who understand that the real vulnerability                 │
│  isn't in the code — it's in what the code exposes.                        │
│                                                                              │
│  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  │
│                                                                              │
│  [+] 100+ Detection Rules     [+] 8 Active Verifiers                        │
│  [+] AST-based Extraction     [+] Enterprise API                            │
│  [+] JWT Decoding             [+] Webhook Alerts                            │
│  [+] SARIF CI/CD Output       [+] Scheduled Scans                           │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## `> ./install.sh`

### Requirements

```
┌─────────────────────────────────────┐
│  Python 3.10+                       │
│  pip (latest)                       │
│  ~50MB disk space                   │
│  Internet connection                │
└─────────────────────────────────────┘
```

### Quick Install

```bash
# Clone the repository
git clone https://github.com/SnailSploit/X-Posure.git
cd X-Posure

# Install dependencies
pip install -r requirements.txt

# Or install as a package (recommended)
pip install -e .

# Verify installation
python -m xposure --version
```

### Docker Install

```bash
# Build the image
docker build -t xposure .

# Run a scan
docker run -it xposure example.com
```

### Manual Dependencies

```bash
# Core dependencies
pip install aiohttp>=3.8.0      # Async HTTP client
pip install aiodns>=3.0.0       # Async DNS resolver
pip install click>=8.0.0        # CLI framework
pip install pyyaml>=6.0.0       # YAML parsing
pip install pyjsparser>=2.7.0   # JavaScript AST (optional)
```

### Verify Everything Works

```bash
# Run the self-test
python -c "
from xposure.storage import get_database
from xposure.api import APIServer
from xposure.verify import AWSVerifier, GitHubVerifier, JWTVerifier
from xposure.output import format_sarif
print('[+] All systems operational')
"
```

---

## `> ./run.sh --help`

### Basic Usage

```bash
# Scan a domain
python -m xposure example.com

# Save results to JSON
python -m xposure example.com -o results.json

# Export as SARIF (for GitHub/GitLab CI)
python -m xposure example.com --format sarif -o results.sarif

# Quiet mode (minimal output)
python -m xposure example.com --quiet

# Skip active verification (passive only)
python -m xposure example.com --no-verify

# Verbose mode (debug output)
python -m xposure example.com -v
```

### API Server Mode

```bash
# Start the REST API server
python -m xposure.api --host 0.0.0.0 --port 8080

# With API key authentication
python -m xposure.api --api-key "your-secret-key"

# Custom database location
python -m xposure.api --db-path /var/lib/xposure/data.db
```

### Scheduled Scanning

```python
from xposure.scheduler import Scheduler, CRON_DAILY

scheduler = Scheduler()

# Add a daily scan
scheduler.add_schedule(
    name="Daily Prod Scan",
    target="https://api.example.com",
    cron_expression=CRON_DAILY,  # "0 0 * * *"
    options={"verify": True}
)

# Start the scheduler
await scheduler.start()
```

---

## `> cat /etc/xposure/features`

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│  ███████╗███████╗ █████╗ ████████╗██╗   ██╗██████╗ ███████╗███████╗         │
│  ██╔════╝██╔════╝██╔══██╗╚══██╔══╝██║   ██║██╔══██╗██╔════╝██╔════╝         │
│  █████╗  █████╗  ███████║   ██║   ██║   ██║██████╔╝█████╗  ███████╗         │
│  ██╔══╝  ██╔══╝  ██╔══██║   ██║   ██║   ██║██╔══██╗██╔══╝  ╚════██║         │
│  ██║     ███████╗██║  ██║   ██║   ╚██████╔╝██║  ██║███████╗███████║         │
│  ╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝         │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Detection Engine (100+ Rules)

| Category | Count | Examples |
|----------|-------|----------|
| ☁️ **Cloud** | 25+ | AWS, GCP, Azure, DigitalOcean, Heroku, Vercel |
| 🤖 **AI/ML** | 16+ | OpenAI, Anthropic, Cohere, HuggingFace, Replicate |
| 📦 **DevOps** | 20+ | GitHub, GitLab, Docker, NPM, PyPI, CircleCI |
| 💬 **Communication** | 15+ | Slack, Discord, Twilio, SendGrid, Mailgun |
| 💳 **Payment** | 10+ | Stripe, PayPal, Square, Plaid, Shopify |
| 🗄️ **Database** | 15+ | MongoDB, PostgreSQL, Redis, Supabase, PlanetScale |

### Active Verifiers (8 Providers)

```
┌─────────────┬────────────────────────────────────────────────────────────────┐
│ Provider    │ Capabilities                                                   │
├─────────────┼────────────────────────────────────────────────────────────────┤
│ AWS         │ STS identity, IAM user/role detection, blast radius           │
│ GitHub      │ User info, OAuth scopes, repo access, org membership          │
│ Slack       │ Workspace, bot/user detection, permission enumeration         │
│ Stripe      │ Account info, live/test detection, charges enabled            │
│ OpenAI      │ Model access, key type, usage capabilities                    │
│ GCP         │ API key validation, service account, OAuth tokens             │
│ Azure       │ Client secrets, SAS tokens, connection strings                │
│ JWT         │ Decode, validate claims, extract identity & permissions       │
└─────────────┴────────────────────────────────────────────────────────────────┘
```

### Enterprise Features

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  [DATABASE]     SQLite persistence for findings, scans, audit logs         │
│  [API]          Full REST API with auth, CRUD for all entities             │
│  [WEBHOOKS]     Slack, generic HTTP with HMAC signing                      │
│  [SCHEDULING]   Cron-based recurring scans with history                    │
│  [METRICS]      Prometheus-compatible counters, gauges, histograms         │
│  [LOGGING]      Structured JSON logging for SIEM integration               │
│  [SARIF]        Static Analysis Results for GitHub/GitLab CI               │
│  [FP MGMT]      False positive suppression with rules                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## `> curl localhost:8080/api/v1`

### REST API Endpoints

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              API REFERENCE                                   │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  HEALTH                                                                      │
│  ───────────────────────────────────────────────────                         │
│  GET  /health                    Health check                                │
│  GET  /api/v1/stats              Overall statistics                          │
│  GET  /metrics                   Prometheus metrics                          │
│                                                                              │
│  SCANS                                                                       │
│  ───────────────────────────────────────────────────                         │
│  POST /api/v1/scans              Create new scan                             │
│  GET  /api/v1/scans              List all scans                              │
│  GET  /api/v1/scans/:id          Get scan details                            │
│  DEL  /api/v1/scans/:id          Cancel running scan                         │
│                                                                              │
│  FINDINGS                                                                    │
│  ───────────────────────────────────────────────────                         │
│  GET  /api/v1/findings           List findings (filterable)                  │
│  GET  /api/v1/findings/:id       Get finding details                         │
│  POST /api/v1/findings/:id/suppress   Mark as false positive                 │
│  DEL  /api/v1/findings/:id/suppress   Remove suppression                     │
│                                                                              │
│  SUPPRESSIONS                                                                │
│  ───────────────────────────────────────────────────                         │
│  GET  /api/v1/suppressions       List suppression rules                      │
│  POST /api/v1/suppressions       Create suppression rule                     │
│  DEL  /api/v1/suppressions/:id   Delete suppression rule                     │
│                                                                              │
│  WEBHOOKS                                                                    │
│  ───────────────────────────────────────────────────                         │
│  GET  /api/v1/webhooks           List webhooks                               │
│  POST /api/v1/webhooks           Create webhook                              │
│  DEL  /api/v1/webhooks/:id       Delete webhook                              │
│                                                                              │
│  AUDIT                                                                       │
│  ───────────────────────────────────────────────────                         │
│  GET  /api/v1/audit              View audit log                              │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Example: Create a Scan

```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-api-key" \
  -d '{
    "target": "https://example.com",
    "options": {
      "verify": true,
      "discover_subdomains": true
    }
  }'
```

### Example: Setup Slack Alerts

```bash
curl -X POST http://localhost:8080/api/v1/webhooks \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Slack Critical Alerts",
    "url": "https://hooks.slack.com/services/XXX/YYY/ZZZ",
    "events": ["finding.critical", "finding.verified"],
    "secret": "optional-hmac-secret"
  }'
```

---

## `> cat /var/log/xposure/scan.log`

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              SAMPLE OUTPUT                                   │
└──────────────────────────────────────────────────────────────────────────────┘

    ██╗  ██╗      ██████╗  ██████╗ ███████╗██╗   ██╗██████╗ ███████╗
    ╚██╗██╔╝      ██╔══██╗██╔═══██╗██╔════╝██║   ██║██╔══██╗██╔════╝
     ╚███╔╝ █████╗██████╔╝██║   ██║███████╗██║   ██║██████╔╝█████╗
     ██╔██╗ ╚════╝██╔═══╝ ██║   ██║╚════██║██║   ██║██╔══██╗██╔══╝
    ██╔╝ ██╗      ██║     ╚██████╔╝███████║╚██████╔╝██║  ██║███████╗
    ╚═╝  ╚═╝      ╚═╝      ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝

    v4.0.0 // ENTERPRISE EDITION
    ─────────────────────────────────────────────────────────────────

[*] Target: evil-corp.com
[*] Scan ID: evil-corp_20251222_031337
[*] Mode: FULL (discovery + extraction + verification)

[DISCOVERY] ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
[+] Querying crt.sh for subdomains...
[+] Found: api.evil-corp.com
[+] Found: staging.evil-corp.com
[+] Found: dev.evil-corp.com
[+] Found: jenkins.evil-corp.com
[+] Discovered 47 subdomains
[+] Discovered 23 JavaScript files
[+] Discovered 156 paths

[EXTRACTION] ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
[+] Analyzing https://dev.evil-corp.com/.env
    └─ AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    └─ AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG...
[+] Analyzing https://jenkins.evil-corp.com/config.js
    └─ GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
[+] Decoded 12 base64 blobs
[+] Found 89 credential candidates

[CORRELATION] ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
[+] Deduplicated: 89 → 24 unique
[+] Paired credentials: 3 pairs found
[+] Average confidence: 0.82

[VERIFICATION] ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
[+] Verifying AWS credentials...
    └─ VERIFIED: IAM User 'deploy-bot' (AdministratorAccess)
    └─ BLAST RADIUS: CRITICAL
[+] Verifying GitHub token...
    └─ VERIFIED: User 'evil-corp-bot' (repo, admin:org)
    └─ BLAST RADIUS: HIGH
[+] Verifying Slack token...
    └─ VERIFIED: Bot 'Jenkins CI' in 'Evil Corp' workspace
    └─ BLAST RADIUS: MEDIUM

════════════════════════════════════════════════════════════════════
                         SCAN COMPLETE
════════════════════════════════════════════════════════════════════

    ┌─────────────────────────────────────────────────────────────┐
    │  CRITICAL: 2   HIGH: 5   MEDIUM: 8   LOW: 9                │
    │  ─────────────────────────────────────────────────────────  │
    │  Verified: 15   Invalid: 4   Errors: 0   Suppressed: 5     │
    │  ─────────────────────────────────────────────────────────  │
    │  Duration: 47.3s   Requests: 1,247   Rate Limited: 0       │
    └─────────────────────────────────────────────────────────────┘

[!] HIGH-VALUE TARGETS IDENTIFIED:

    ╔═══════════════════════════════════════════════════════════════╗
    ║  #1  AWS IAM Credentials (CRITICAL)                          ║
    ║      Identity: arn:aws:iam::123456789:user/deploy-bot        ║
    ║      Access: AdministratorAccess                              ║
    ║      Source: https://dev.evil-corp.com/.env:12               ║
    ╠═══════════════════════════════════════════════════════════════╣
    ║  #2  GitHub Personal Access Token (HIGH)                      ║
    ║      Identity: evil-corp-bot                                  ║
    ║      Scopes: repo, admin:org, write:packages                 ║
    ║      Source: https://jenkins.evil-corp.com/config.js:847    ║
    ╚═══════════════════════════════════════════════════════════════╝

[*] Results saved to: evil-corp_findings.json
[*] SARIF report: evil-corp_findings.sarif
```

---

## `> tree /opt/xposure`

```
X-Posure/
├── xposure/
│   ├── __init__.py
│   ├── cli.py                    # CLI interface
│   ├── config.py                 # Configuration
│   │
│   ├── core/                     # Core engine
│   │   ├── engine.py             # Main scanning engine
│   │   ├── models.py             # Data models
│   │   └── graph.py              # Evidence graph
│   │
│   ├── discover/                 # Discovery modules
│   │   ├── subdomains.py         # Subdomain enumeration
│   │   ├── paths.py              # Path discovery
│   │   ├── js.py                 # JavaScript harvesting
│   │   └── github.py             # GitHub dorking
│   │
│   ├── extract/                  # Extraction pipeline
│   │   ├── quick.py              # Regex scanner
│   │   ├── decode.py             # Decode chain
│   │   ├── ast.py                # JavaScript AST parser
│   │   └── objects.py            # Object extraction
│   │
│   ├── rules/                    # Detection rules
│   │   ├── cloud.yaml            # Cloud providers
│   │   ├── ai.yaml               # AI/ML services
│   │   ├── devtools.yaml         # DevOps tools
│   │   └── cloud_services.yaml   # SaaS platforms
│   │
│   ├── verify/                   # Verification engines
│   │   ├── aws.py                # AWS STS
│   │   ├── github.py             # GitHub API
│   │   ├── gcp.py                # Google Cloud
│   │   ├── azure.py              # Microsoft Azure
│   │   ├── jwt.py                # JWT decoder
│   │   └── ...                   # Slack, Stripe, OpenAI
│   │
│   ├── api/                      # REST API [ENTERPRISE]
│   │   ├── server.py             # aiohttp server
│   │   └── webhooks.py           # Webhook notifications
│   │
│   ├── storage/                  # Persistence [ENTERPRISE]
│   │   └── database.py           # SQLite backend
│   │
│   ├── scheduler/                # Scheduling [ENTERPRISE]
│   │   └── scheduler.py          # Cron-based scheduler
│   │
│   ├── observability/            # Monitoring [ENTERPRISE]
│   │   ├── logging.py            # Structured logging
│   │   └── metrics.py            # Prometheus metrics
│   │
│   ├── output/                   # Output formats
│   │   ├── console.py            # Terminal output
│   │   └── sarif.py              # SARIF format
│   │
│   └── wordlists/                # Discovery wordlists
│       ├── subdomains.txt        # 150+ prefixes
│       └── paths.txt             # 200+ paths
│
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

## `> cat /etc/xposure/legal.txt`

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                         ⚠️  LEGAL DISCLAIMER  ⚠️                             │
│                                                                              │
│  This tool is designed for AUTHORIZED security testing only.                │
│                                                                              │
│  ✅ LEGAL:                                                                   │
│     • Testing systems you own                                                │
│     • Bug bounty programs with explicit permission                          │
│     • Authorized penetration testing engagements                            │
│     • Security research with proper authorization                           │
│                                                                              │
│  ❌ ILLEGAL:                                                                 │
│     • Unauthorized access to systems                                         │
│     • Credential harvesting without permission                              │
│     • Using discovered credentials maliciously                              │
│     • Any activity violating computer crime laws                            │
│                                                                              │
│  YOU are responsible for ensuring you have permission.                       │
│  The authors assume NO liability for misuse.                                │
│                                                                              │
│  "With great power comes great responsibility."                              │
│     - Uncle Ben (and every security researcher ever)                        │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## `> echo $CREDITS`

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│     ███████╗███╗   ██╗ █████╗ ██╗██╗     ███████╗██████╗ ██╗      ██████╗   │
│     ██╔════╝████╗  ██║██╔══██╗██║██║     ██╔════╝██╔══██╗██║     ██╔═══██╗  │
│     ███████╗██╔██╗ ██║███████║██║██║     ███████╗██████╔╝██║     ██║   ██║  │
│     ╚════██║██║╚██╗██║██╔══██║██║██║     ╚════██║██╔═══╝ ██║     ██║   ██║  │
│     ███████║██║ ╚████║██║  ██║██║███████╗███████║██║     ███████╗╚██████╔╝  │
│     ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   │
│                                                                              │
│                        https://github.com/SnailSploit                       │
│                                                                              │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  Built with:                                                                 │
│    • Python 3.10+      • aiohttp           • PyYAML                         │
│    • Click             • aiodns            • pyjsparser                     │
│                                                                              │
│  Inspired by:                                                                │
│    • The security community                                                  │
│    • Late night CTFs                                                         │
│    • That one .env file in production                                       │
│                                                                              │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│                    "Hello, friend." - Mr. Robot                              │
│                                                                              │
│                   [ Made with ☕ and existential dread ]                     │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

<p align="center">
  <code>[ EOF ]</code>
</p>

<p align="center">
  <sub>You didn't see anything. This README will self-destruct in 5... 4... just kidding.</sub>
</p>
