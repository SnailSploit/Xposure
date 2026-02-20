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
    █  [ v4.0.0 ]  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  [ ENTERPRISE ]   █
    █                                                                        █
    █  "Control is an illusion. But credentials? Those are real."            █
    █                                                    - Mr. Robot, maybe  █
    █                                                                        █
    ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀

                    [ The shit your DevOps forgot. ]
                              by SnailSploit
```

<p align="center">
  <img src="assets/banner.png" width="700" alt="X-POSURE by SnailSploit">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-4.0.0-ff0040?style=for-the-badge&labelColor=1a1a2e" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10+-00d4ff?style=for-the-badge&labelColor=1a1a2e" alt="Python">
  <img src="https://img.shields.io/badge/status-OPERATIONAL-00ff41?style=for-the-badge&labelColor=1a1a2e" alt="Status">
  <img src="https://img.shields.io/badge/license-MIT-9d4edd?style=for-the-badge&labelColor=1a1a2e" alt="License">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/recursive_crawl-NEW-ff6b35?style=for-the-badge&labelColor=1a1a2e" alt="Recursive Crawl">
  <img src="https://img.shields.io/badge/shodan-INTEGRATED-e040fb?style=for-the-badge&labelColor=1a1a2e" alt="Shodan">
  <img src="https://img.shields.io/badge/claude_AI-POWERED-f5a623?style=for-the-badge&labelColor=1a1a2e" alt="AI">
  <img src="https://img.shields.io/badge/trufflehog-SECRETS-00e5ff?style=for-the-badge&labelColor=1a1a2e" alt="TruffleHog">
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
│  v4.0 adds recursive crawling with evasion, Shodan infrastructure mapping, │
│  Claude AI-powered contextual analysis, and TruffleHog deep secrets scan.  │
│                                                                              │
│  Built for those who understand that the real vulnerability                 │
│  isn't in the code — it's in what the code exposes.                        │
│                                                                              │
│  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  │
│                                                                              │
│  [+] 100+ Detection Rules     [+] 8 Active Verifiers                       │
│  [+] AST-based Extraction     [+] Enterprise API                           │
│  [+] JWT Decoding             [+] Webhook Alerts                           │
│  [+] SARIF CI/CD Output       [+] Scheduled Scans                          │
│  [+] Recursive Crawling       [+] Shodan Recon                             │
│  [+] AI-Powered Analysis      [+] TruffleHog Secrets                       │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## `> diff v3 v4 --stat`

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│  ██╗    ██╗██╗  ██╗ █████╗ ████████╗███████╗    ███╗   ██╗███████╗██╗    ██╗│
│  ██║    ██║██║  ██║██╔══██╗╚══██╔══╝██╔════╝    ████╗  ██║██╔════╝██║    ██║│
│  ██║ █╗ ██║███████║███████║   ██║   ███████╗    ██╔██╗ ██║█████╗  ██║ █╗ ██║│
│  ██║███╗██║██╔══██║██╔══██║   ██║   ╚════██║    ██║╚██╗██║██╔══╝  ██║███╗██║│
│  ╚███╔███╔╝██║  ██║██║  ██║   ██║   ███████║    ██║ ╚████║███████╗╚███╔███╔╝│
│   ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝    ╚═╝  ╚═══╝╚══════╝ ╚══╝╚══╝│
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Recursive Crawl Engine (`-rc`)

| Feature | Description |
|---------|-------------|
| **Smart Crawling** | Depth-limited recursive spider with configurable max pages |
| **Evasion Suite** | User-Agent rotation, browser fingerprints, referer spoofing |
| **Rate Limiting** | Configurable random sleep intervals between requests |
| **Content Extraction** | Inline secrets scanning on every crawled page |
| **Link Following** | Same-domain link discovery with depth tracking |

### Shodan Infrastructure Mapping (`--shodan-key`)

| Feature | Description |
|---------|-------------|
| **Host Recon** | Open ports, services, banners, OS detection |
| **CVE Lookup** | Known vulnerabilities on exposed services |
| **SSL/TLS Intel** | Certificate details, expiry, issuer chain |
| **Geo/ASN Data** | ISP, organization, physical location |
| **Attack Surface** | Full infrastructure map from a single domain |

### AI-Powered Analysis (`--anthropic-key`)

| Feature | Description |
|---------|-------------|
| **Context Engine** | Claude analyzes findings with full scan context |
| **Risk Scoring** | AI-generated severity and blast radius assessment |
| **Exploit Paths** | Identifies credential chaining opportunities |
| **Remediation** | Actionable fix recommendations per finding |
| **Executive Summary** | Natural language report generation |

### TruffleHog Deep Scan

| Feature | Description |
|---------|-------------|
| **600+ Detectors** | Covers every major SaaS, cloud, and dev platform |
| **Verified Secrets** | Active verification built into TruffleHog |
| **Inline Pipeline** | Runs on every crawled page automatically |
| **Dedup & Merge** | Results merged with X-POSURE's own findings |

---

## `> ./install.sh`

### Requirements

```
┌─────────────────────────────────────┐
│  Python 3.10+                       │
│  pip (latest)                       │
│  ~50MB disk space                   │
│  Internet connection                │
│                                     │
│  Optional:                          │
│  trufflehog (for deep scan)         │
│  shodan (pip install shodan)        │
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

# Optional: install TruffleHog for deep secrets scanning
# See: https://github.com/trufflesecurity/trufflehog

# Verify installation
python -m xposure --version
```

### Docker Install

```bash
# Build the image
docker build -t xposure .

# Run a scan
docker run -it xposure example.com

# Recursive crawl with Shodan + AI
docker run -it xposure example.com -rc --shodan-key XXXXX --anthropic-key sk-ant-XXX
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
```

### Recursive Crawl Mode (NEW)

```bash
# Basic recursive crawl with evasion
python -m xposure example.com -rc

# Deep crawl with custom depth and page limit
python -m xposure example.com -rc --crawl-depth 10 --crawl-max-pages 1000

# Stealth mode: slow crawl with wide sleep intervals
python -m xposure example.com -rc --crawl-sleep 3.0 8.0

# Full recon: crawl + Shodan + AI analysis
python -m xposure example.com -rc --shodan-key YOUR_KEY --anthropic-key sk-ant-XXX

# Disable TruffleHog (regex-only mode)
python -m xposure example.com -rc --no-trufflehog
```

### CLI Reference

```
Usage: python -m xposure [OPTIONS] [TARGET]

Options:
  -g, --github-token TEXT      GitHub token for dorking
  -o, --output PATH            Output file (JSON)
  -q, --quiet                  Minimal output
  --no-verify                  Skip active verification
  -v, --version                Show version

  Recursive Crawl:
  -rc, --recursive-crawl       Enable recursive crawl with evasion
  --crawl-depth INTEGER        Max crawl depth (default: 5)
  --crawl-max-pages INTEGER    Max pages to crawl (default: 500)
  --crawl-sleep FLOAT FLOAT    Min/max sleep between requests (default: 1.0 3.0)
  --no-trufflehog              Disable TruffleHog secrets scanning

  Integrations:
  --shodan-key TEXT            Shodan API key for infrastructure mapping
  --anthropic-key TEXT         Anthropic API key for AI-powered analysis
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
| **Cloud** | 25+ | AWS, GCP, Azure, DigitalOcean, Heroku, Vercel |
| **AI/ML** | 16+ | OpenAI, Anthropic, Cohere, HuggingFace, Replicate |
| **DevOps** | 20+ | GitHub, GitLab, Docker, NPM, PyPI, CircleCI |
| **Communication** | 15+ | Slack, Discord, Twilio, SendGrid, Mailgun |
| **Payment** | 10+ | Stripe, PayPal, Square, Plaid, Shopify |
| **Database** | 15+ | MongoDB, PostgreSQL, Redis, Supabase, PlanetScale |

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

### Recursive Crawl Engine

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  [SPIDER]      Depth-limited recursive crawl with link extraction          │
│  [EVASION]     User-Agent rotation from 10+ real browser profiles          │
│  [FINGERPRINT] Full browser fingerprint headers (Accept, Encoding, etc.)   │
│  [STEALTH]     Random sleep intervals + referer chain spoofing             │
│  [TRUFFLEHOG]  Inline TruffleHog scanning on every crawled page            │
│  [SHODAN]      Infrastructure mapping: ports, CVEs, SSL, geo, ASN         │
│  [CLAUDE AI]   Contextual analysis, risk scoring, remediation advice       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
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

### Example: Full Recon Scan via API

```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-api-key" \
  -d '{
    "target": "https://example.com",
    "options": {
      "verify": true,
      "recursive_crawl": true,
      "crawl_depth": 10,
      "shodan_key": "YOUR_SHODAN_KEY",
      "anthropic_key": "sk-ant-YOUR_KEY"
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
[*] Mode: FULL RECON (crawl + shodan + ai + trufflehog)

[RECURSIVE CRAWL] ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
[+] Crawling https://evil-corp.com (depth 0)
[+] User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...
[+] Discovered 47 links → queuing depth 1
[+] Sleeping 2.3s (evasion)
[+] Crawling https://evil-corp.com/api/config (depth 1)
[+] TruffleHog: 3 verified secrets on this page
[+] Crawled 312 pages across 5 depth levels

[SHODAN RECON] ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
[+] evil-corp.com → 203.0.113.42
[+] Open ports: 22, 80, 443, 3306, 6379, 8080, 9200
[+] CVE-2024-21762 (Fortinet FortiOS) — CRITICAL
[+] CVE-2023-44487 (HTTP/2 Rapid Reset) — HIGH
[+] Redis 7.0.11 exposed on port 6379 (no auth)
[+] Elasticsearch 8.x on port 9200 (no auth)

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

[AI ANALYSIS] ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
[+] Claude analyzing 24 findings with full context...
[+] Risk Assessment: CRITICAL — Admin AWS keys + exposed Redis = full takeover
[+] Attack Chain: .env → AWS Admin → S3 buckets → lateral movement
[+] Remediation: 7 actionable recommendations generated

════════════════════════════════════════════════════════════════════
                         SCAN COMPLETE
════════════════════════════════════════════════════════════════════

    ┌─────────────────────────────────────────────────────────────┐
    │  CRITICAL: 4   HIGH: 7   MEDIUM: 8   LOW: 5                │
    │  ─────────────────────────────────────────────────────────  │
    │  Verified: 18   Invalid: 4   Errors: 0   Suppressed: 2     │
    │  ─────────────────────────────────────────────────────────  │
    │  Pages Crawled: 312  Shodan Hosts: 3  AI Insights: 7       │
    │  ─────────────────────────────────────────────────────────  │
    │  Duration: 94.7s   Requests: 2,847   Rate Limited: 0       │
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
    ╠═══════════════════════════════════════════════════════════════╣
    ║  #3  Redis (NO AUTH) + Elasticsearch (NO AUTH) (CRITICAL)    ║
    ║      Shodan: 203.0.113.42:6379, 203.0.113.42:9200           ║
    ║      Risk: Unauthenticated data stores on public internet    ║
    ╚═══════════════════════════════════════════════════════════════╝

[*] Results saved to: evil-corp_findings.json
[*] SARIF report: evil-corp_findings.sarif
[*] AI report: evil-corp_ai_analysis.md
```

---

## `> tree /opt/xposure`

```
X-Posure/
├── assets/                      # Logos & media
│
├── xposure/
│   ├── __init__.py
│   ├── cli.py                    # CLI interface (Click)
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
│   ├── crawl/                    # Recursive crawl engine [NEW]
│   │   └── recursive.py          # Spider + evasion + TruffleHog
│   │
│   ├── intel/                    # Intelligence integrations [NEW]
│   │   ├── shodan_recon.py       # Shodan infrastructure mapping
│   │   └── ai_analysis.py        # Claude AI-powered analysis
│   │
│   ├── rules/                    # Detection rules (YAML)
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
├── tests/
│   ├── test_recursive_crawl.py   # Crawl engine tests (16 tests)
│   ├── test_rules.py             # Detection rule tests
│   ├── test_extraction.py        # Extraction pipeline tests
│   ├── test_correlation.py       # Correlation engine tests
│   └── test_verification.py      # Verifier tests
│
├── Dockerfile
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

<p align="center">
  <sub>https://github.com/SnailSploit</sub>
</p>
