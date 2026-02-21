# X-POSURE v5.0

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
    █  [ v5.0.0 ]  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  [ APEX ]        █
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
  <img src="https://img.shields.io/badge/version-5.0.0-ff0040?style=for-the-badge&labelColor=1a1a2e" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10+-00d4ff?style=for-the-badge&labelColor=1a1a2e" alt="Python">
  <img src="https://img.shields.io/badge/codename-APEX-ff6b35?style=for-the-badge&labelColor=1a1a2e" alt="Codename">
  <img src="https://img.shields.io/badge/license-MIT-9d4edd?style=for-the-badge&labelColor=1a1a2e" alt="License">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/24_verifiers-NEW-00ff41?style=for-the-badge&labelColor=1a1a2e" alt="24 Verifiers">
  <img src="https://img.shields.io/badge/internal_scan-NEW-e040fb?style=for-the-badge&labelColor=1a1a2e" alt="Internal Scan">
  <img src="https://img.shields.io/badge/git_mining-NEW-f5a623?style=for-the-badge&labelColor=1a1a2e" alt="Git Mining">
  <img src="https://img.shields.io/badge/combined_mode-NEW-00e5ff?style=for-the-badge&labelColor=1a1a2e" alt="Combined Mode">
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
│  target's entire attack surface — inside and out.                           │
│                                                                              │
│  v5.0 "APEX" is the everything release:                                    │
│                                                                              │
│    Outside-in recon + inside-out container scanning + git history mining    │
│    + recursive crawling + credential verification across 24 platforms.     │
│                                                                              │
│  Built for those who understand that the real vulnerability                 │
│  isn't in the code — it's in what the code exposes.                        │
│                                                                              │
│  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  │
│                                                                              │
│  [+] 100+ Detection Rules     [+] 24 Active Verifiers                     │
│  [+] AST-based Extraction     [+] Enterprise API                           │
│  [+] JWT Decoding             [+] Webhook Alerts                           │
│  [+] SARIF + HTML Reports     [+] Scheduled Scans                          │
│  [+] Recursive Crawling       [+] Shodan Recon                             │
│  [+] AI-Powered Analysis      [+] TruffleHog Secrets                       │
│  [+] Git History Mining       [+] Internal/Container Scan                  │
│  [+] TLS Certificate Harvest  [+] Wayback Machine                          │
│  [+] Cloud Storage Enum       [+] Network Probing                          │
│  [+] DNS Enumeration          [+] State Persistence + Resume               │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## `> diff v4 v5 --stat`

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

### Inside-Out Scanning (NEW)

| Feature | Description |
|---------|-------------|
| **Internal Mode** (`--internal`) | Scans the local container/server environment for leaked secrets |
| **Network Probing** | Discovers internal services, metadata endpoints, cloud IMDS |
| **Environment Scan** | Reads env vars, config files, mounted secrets |
| **Container Detection** | Detects Docker, Kubernetes, ECS, and cloud compute contexts |

### Git History Mining (NEW)

| Feature | Description |
|---------|-------------|
| **Local Repos** (`--git /path`) | Deep scan of commit history for secrets |
| **Remote Repos** (`--git https://...`) | Clone and scan remote repositories |
| **TruffleHog Integration** | 600+ detectors with verification |
| **Diff Analysis** | Scans diffs, not just current state |

### Combined Mode (NEW)

| Feature | Description |
|---------|-------------|
| **Full Spectrum** (`--combined`) | Runs external + internal + git scans together |
| **Unified Correlation** | Cross-references findings across all scan modes |
| **Single Report** | Consolidated output across all attack surfaces |

### 24 Credential Verifiers (UP FROM 8)

| Category | Verifiers |
|----------|-----------|
| **Cloud** | AWS, Azure, GCP, Heroku, DigitalOcean, Cloudflare |
| **VCS/Registries** | GitHub, NPM, PyPI, Supabase |
| **Communication** | Slack, Discord, Telegram, Twilio |
| **Payment/APIs** | Stripe, SendGrid, Shodan, OpenAI, Anthropic |
| **Databases** | MongoDB, PostgreSQL, Redis, Vault |
| **Auth** | JWT decode + claim validation |

### Expanded Discovery

| Feature | Description |
|---------|-------------|
| **TLS Certificate Harvest** | Extracts domains and orgs from certificate chains |
| **DNS Enumeration** | Zone transfers, record type enumeration, brute force |
| **Wayback Machine** | Historical URL discovery from the Internet Archive |
| **Cloud Storage** | S3 bucket, GCS bucket, Azure blob enumeration |
| **Source Maps** | Discovers and parses `.map` files for original source |
| **Config Files** | Detects exposed `.env`, `config.js`, `settings.py`, etc. |

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
│  gitpython (pip install gitpython)  │
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

# Install with all optional dependencies
pip install -e '.[full]'

# Or pick what you need
pip install -e '.[recon]'    # Shodan + Anthropic AI
pip install -e '.[git]'      # Git history scanning
pip install -e '.[db]'       # Database verifiers (MongoDB, Postgres, Redis)

# Optional: install TruffleHog for deep secrets scanning
# See: https://github.com/trufflesecurity/trufflehog

# Verify installation
xposure --version
```

### Docker Install

```bash
# Build the image
docker build -t xposure .

# Run a scan
docker run -it xposure scan example.com

# Full recon: crawl + Shodan + AI + internal
docker run -it xposure scan example.com --combined -rc --shodan-key XXXXX --anthropic-key sk-ant-XXX
```

---

## `> xposure --help`

### Basic Usage

```bash
# Scan a domain
xposure scan example.com

# Save results to JSON
xposure scan example.com -o results.json

# Export as SARIF (for GitHub/GitLab CI)
xposure scan example.com --sarif results.sarif

# Export as HTML report
xposure scan example.com --html report.html

# Quiet mode (minimal output)
xposure scan example.com --quiet

# Skip active verification (passive only)
xposure scan example.com --no-verify

# Show raw credential values (unmasked)
xposure scan example.com --unmask
```

### Scan Modes

```bash
# Standard external scan
xposure scan example.com

# Recursive crawl with evasion
xposure scan example.com -rc

# Deep crawl with custom depth and page limit
xposure scan example.com -rc --crawl-depth 10 --crawl-max-pages 1000

# Stealth mode: slow crawl with wide sleep intervals
xposure scan example.com -rc --crawl-sleep 3.0 8.0

# Internal container/server scan
xposure scan --internal

# Git history scan (local repo)
xposure scan --git /path/to/repo

# Git history scan (remote repo)
xposure scan --git https://github.com/org/repo.git

# Scan a local directory for secrets
xposure scan --file /path/to/code

# COMBINED: everything at once
xposure scan --combined example.com -rc --git ./ --internal

# Full recon: crawl + Shodan + AI analysis
xposure scan example.com -rc --shodan-key YOUR_KEY --anthropic-key sk-ant-XXX

# Resume a previous scan
xposure scan example.com --resume scan_id_here
```

### Other Commands

```bash
# Re-verify findings from a previous scan
xposure verify findings.json

# Generate reports from previous scan results
xposure report findings.json --html report.html
xposure report findings.json --sarif results.sarif

# Diff two scan results to find new/removed findings
xposure diff old_findings.json new_findings.json
```

### Config File

Create `.xposure.yaml` in your project root:

```yaml
target: example.com

modes:
  recursive_crawl: true
  internal: false
  git: ./

keys:
  shodan: YOUR_SHODAN_KEY
  github: ghp_xxxxxxxxxxxx
  anthropic: sk-ant-xxxxxxxxxxxx
```

```bash
# Use default .xposure.yaml
xposure scan

# Use a custom config file
xposure scan -c /path/to/config.yaml
```

### CLI Reference

```
Usage: xposure [OPTIONS] COMMAND [ARGS]

Commands:
  scan      Scan a target for exposed credentials
  verify    Re-verify findings from a previous scan
  report    Generate reports from previous scan results
  diff      Diff two scan results to find new/removed findings

Scan Options:
  TARGET                           Domain or URL to scan
  -g, --github-token TEXT          GitHub token for dorking
  -o, --output PATH                Output file (JSON)
  -q, --quiet                      Minimal output
  -v, --version                    Show version
  -c, --config PATH                Config file path (default: .xposure.yaml)
  --no-verify                      Skip active verification
  --unmask                         Show raw credential values in output
  --resume TEXT                    Resume scan from state file

  Scan Modes:
  -i, --internal                   Scan local container/server environment
  --git TEXT                       Scan git repo (path or URL)
  --file PATH                      Scan local directory for secrets
  --combined                       Run all scan modes together

  Recursive Crawl:
  -rc, --recursive-crawl           Enable recursive crawl with evasion
  --crawl-depth INTEGER            Max crawl depth (default: 5)
  --crawl-max-pages INTEGER        Max pages to crawl (default: 500)
  --crawl-sleep FLOAT FLOAT        Min/max sleep between requests (default: 1.0 3.0)
  --no-trufflehog                  Disable TruffleHog secrets scanning

  Integrations:
  --shodan-key TEXT                Shodan API key for infrastructure mapping
  --anthropic-key TEXT             Anthropic API key for AI-powered analysis

  Output:
  --sarif PATH                     Also output SARIF file
  --html PATH                      Also output HTML report
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

### Detection Engine (100+ Rules across 8 Categories)

| Category | File | Examples |
|----------|------|----------|
| **Cloud** | `cloud.yaml` | AWS, GCP, Azure, DigitalOcean, Heroku, Vercel |
| **AI/ML** | `ai.yaml` | OpenAI, Anthropic, Cohere, HuggingFace, Replicate |
| **DevOps** | `devtools.yaml` | Docker, CircleCI, Jenkins, Terraform |
| **Communication** | `communication.yaml` | Slack, Discord, Twilio, SendGrid, Mailgun |
| **Payment** | `payment.yaml` | Stripe, PayPal, Square, Plaid, Shopify |
| **Database** | `database.yaml` | MongoDB, PostgreSQL, Redis, Supabase, PlanetScale |
| **VCS** | `vcs.yaml` | GitHub, GitLab, Bitbucket, NPM, PyPI |
| **Cloud Services** | `cloud_services.yaml` | Cloudflare, Fastly, Akamai, Firebase |

### Active Verifiers (24 Providers)

```
┌─────────────────┬──────────────────────────────────────────────────────────┐
│ Provider        │ Capabilities                                             │
├─────────────────┼──────────────────────────────────────────────────────────┤
│ AWS             │ STS identity, IAM user/role, blast radius               │
│ Azure           │ Client secrets, SAS tokens, connection strings          │
│ GCP             │ API key validation, service account, OAuth              │
│ GitHub          │ User info, scopes, repo access, org membership         │
│ Heroku          │ App access, account info                                │
│ DigitalOcean    │ Account info, droplet access                            │
│ Cloudflare      │ Zone access, API permissions                            │
│ Slack           │ Workspace, bot/user detection, permissions              │
│ Discord         │ Bot token validation, guild access                      │
│ Telegram        │ Bot token validation, bot info                          │
│ Twilio          │ Account SID, API key validation                        │
│ Stripe          │ Account info, live/test detection                      │
│ SendGrid        │ API key validation, scopes                              │
│ OpenAI          │ Model access, key type, usage                          │
│ Anthropic       │ API key validation, model access                       │
│ Shodan          │ API key validation, query credits                      │
│ NPM             │ Token validation, publish access                        │
│ PyPI            │ Token validation, package access                        │
│ Supabase        │ Project access, API key type                            │
│ MongoDB         │ Connection test, database enumeration                   │
│ PostgreSQL      │ Connection test, table enumeration                      │
│ Redis           │ Connection test, info extraction                        │
│ Vault           │ Token validation, policy access                         │
│ JWT             │ Decode, validate claims, extract identity              │
└─────────────────┴──────────────────────────────────────────────────────────┘
```

### 9-Phase Scan Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  Phase 1: PASSIVE RECON                                                    │
│  ─────────────────────────────────────────────────────────                  │
│  [SUBDOMAINS]  crt.sh, brute force, DNS enumeration                       │
│  [TLS]         Certificate chain harvest, SAN extraction                  │
│  [DNS]         Zone transfers, record enumeration                          │
│  [WAYBACK]     Historical URL discovery from Internet Archive             │
│  [CLOUD]       S3/GCS/Azure blob bucket enumeration                       │
│                                                                             │
│  Phase 2: ACTIVE CRAWLING                                                  │
│  ─────────────────────────────────────────────────────────                  │
│  [SPIDER]      Depth-limited recursive crawl with link extraction         │
│  [EVASION]     User-Agent rotation, browser fingerprints                  │
│  [JS]          JavaScript file discovery + inline script extraction       │
│  [AST]         JavaScript AST parsing for embedded credentials            │
│  [CONFIGS]     Exposed config file detection (.env, config.js, etc.)      │
│  [SOURCEMAPS]  .map file discovery + original source extraction           │
│                                                                             │
│  Phase 3: SECRET DETECTION                                                 │
│  ─────────────────────────────────────────────────────────                  │
│  [RULES]       100+ regex patterns across 8 YAML rule categories          │
│  [ENTROPY]     Shannon entropy analysis for unknown patterns              │
│  [JWT]         JWT pre-scanning, decoding, claim extraction               │
│  [DECODE]      Multi-layer decode chain (base64, hex, URL, etc.)          │
│  [TRUFFLEHOG]  600+ verified detectors (inline pipeline)                  │
│                                                                             │
│  Phase 4: INTERNAL / CONTAINER SCAN                                        │
│  ─────────────────────────────────────────────────────────                  │
│  [ENV]         Environment variable scanning                               │
│  [MOUNTS]      Mounted secrets / config file detection                     │
│  [METADATA]    Cloud IMDS endpoint probing (AWS, GCP, Azure)              │
│  [NETWORK]     Internal service discovery + port probing                   │
│                                                                             │
│  Phase 5: GIT HISTORY MINING                                               │
│  ─────────────────────────────────────────────────────────                  │
│  [COMMITS]     Full commit history scanning                                │
│  [DIFFS]       Diff-based secret detection                                 │
│  [TRUFFLEHOG]  Deep git history scan with verified detectors              │
│                                                                             │
│  Phase 6: VERIFICATION                                                     │
│  ─────────────────────────────────────────────────────────                  │
│  [COORDINATOR] Routes findings to the right verifier                      │
│  [24 VERIFIERS] Active credential validation across platforms             │
│  [IDENTITY]    Determines who/what the credential belongs to              │
│  [BLAST RADIUS] Assesses potential damage (CRITICAL → LOW)               │
│                                                                             │
│  Phase 7: OUTSIDE-IN ENHANCEMENT                                           │
│  ─────────────────────────────────────────────────────────                  │
│  [DNS]         Bulk domain resolution                                      │
│  [SHODAN]      Infrastructure mapping: ports, CVEs, SSL, geo             │
│  [FINGERPRINT] Technology fingerprinting on exposed services              │
│                                                                             │
│  Phase 8: CORRELATION ENGINE                                               │
│  ─────────────────────────────────────────────────────────                  │
│  [DEDUP]       Candidate deduplication + merge                            │
│  [PAIRING]     Credential pair detection (key + secret)                   │
│  [CONFIDENCE]  Multi-signal confidence scoring                             │
│  [AI]          Claude-powered contextual risk analysis                     │
│                                                                             │
│  Phase 9: REPORTING                                                        │
│  ─────────────────────────────────────────────────────────                  │
│  [JSON]        Structured findings export                                  │
│  [SARIF]       GitHub/GitLab CI integration                                │
│  [HTML]        Rich HTML report with findings + infrastructure             │
│  [CONSOLE]     Live Rich dashboard during scan                             │
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
│  [HTML]         Rich HTML reports with infrastructure mapping              │
│  [STATE]        Scan state persistence + resume capability                 │
│  [FP MGMT]      False positive suppression with rules                      │
│  [CONFIG]       YAML config file support (.xposure.yaml)                   │
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
      "internal": true,
      "git": "./",
      "combined": true,
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

    v5.0.0 // APEX
    ─────────────────────────────────────────────────────────────────

[*] Target: evil-corp.com
[*] Scan ID: evil-corp_20260221_031337
[*] Mode: COMBINED (external + internal + git + crawl + shodan + ai)

[RECURSIVE CRAWL] ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
[+] Crawling https://evil-corp.com (depth 0)
[+] User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...
[+] Discovered 47 links → queuing depth 1
[+] Sleeping 2.3s (evasion)
[+] Crawling https://evil-corp.com/api/config (depth 1)
[+] TruffleHog: 3 verified secrets on this page
[+] Crawled 312 pages across 5 depth levels

[INTERNAL SCAN] ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
[+] Detected: Docker container (ECS Fargate)
[+] AWS IMDS: IAM role 'ecs-task-role' available
[+] Environment: 4 secrets found in env vars
[+] Mounted: /run/secrets/db_password

[GIT HISTORY] ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
[+] Scanning 1,247 commits in ./
[+] Found AWS key in commit abc1234 (removed 3 months ago)
[+] TruffleHog: 5 verified secrets in git history

[SHODAN RECON] ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
[+] evil-corp.com → 203.0.113.42
[+] Open ports: 22, 80, 443, 3306, 6379, 8080, 9200
[+] CVE-2024-21762 (Fortinet FortiOS) — CRITICAL
[+] Redis 7.0.11 exposed on port 6379 (no auth)
[+] Elasticsearch 8.x on port 9200 (no auth)

[DISCOVERY] ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
[+] Querying crt.sh for subdomains...
[+] TLS harvest: 12 domains from certificate chains
[+] DNS enum: zone transfer successful on ns1.evil-corp.com
[+] Wayback: 847 historical URLs discovered
[+] Found: api.evil-corp.com, staging.evil-corp.com, dev.evil-corp.com
[+] Discovered 47 subdomains, 23 JavaScript files, 156 paths

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
    │  CRITICAL: 6   HIGH: 9   MEDIUM: 8   LOW: 5                │
    │  ─────────────────────────────────────────────────────────  │
    │  Verified: 22   Invalid: 4   Errors: 0   Suppressed: 2     │
    │  ─────────────────────────────────────────────────────────  │
    │  Pages Crawled: 312  Shodan Hosts: 3  AI Insights: 7       │
    │  Git Commits: 1247   Internal Hits: 4  Pairs: 3            │
    │  ─────────────────────────────────────────────────────────  │
    │  Duration: 127.3s   Requests: 3,912   Rate Limited: 0      │
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
    ╠═══════════════════════════════════════════════════════════════╣
    ║  #4  AWS IAM Role from Git History (HIGH)                    ║
    ║      Found in: commit abc1234 (deleted 3 months ago)         ║
    ║      Still valid: YES                                         ║
    ╚═══════════════════════════════════════════════════════════════╝

[*] Results saved to: evil-corp_findings.json
[*] SARIF report: evil-corp_findings.sarif
[*] HTML report: evil-corp_report.html
[*] AI report: evil-corp_ai_analysis.md
```

---

## `> tree /opt/xposure`

```
X-Posure/
├── assets/                          # Logos & media
│
├── xposure/
│   ├── __init__.py
│   ├── __main__.py                  # python -m xposure
│   ├── __version__.py               # Version: 5.0.0 "APEX"
│   ├── cli.py                       # CLI interface (Click)
│   ├── config.py                    # Configuration
│   ├── state.py                     # Scan state persistence + resume
│   │
│   ├── core/                        # Core engine
│   │   ├── engine.py                # Main 9-phase scanning engine
│   │   ├── models.py                # Data models
│   │   └── graph.py                 # Evidence relationship graph
│   │
│   ├── discover/                    # Discovery modules (20 files)
│   │   ├── base.py                  # Base discoverer class
│   │   ├── subdomains.py            # Subdomain enumeration (crt.sh, brute)
│   │   ├── dns_enum.py              # DNS enumeration + zone transfers
│   │   ├── tls_harvest.py           # TLS certificate chain harvest
│   │   ├── paths.py                 # Path/endpoint discovery
│   │   ├── js.py                    # JavaScript file harvesting
│   │   ├── configs.py               # Exposed config file detection
│   │   ├── sourcemaps.py            # Source map discovery + parsing
│   │   ├── github.py                # GitHub dorking
│   │   ├── crawler.py               # Recursive crawl spider + evasion
│   │   ├── fingerprints.py          # Browser fingerprint rotation
│   │   ├── trufflehog.py            # TruffleHog integration
│   │   ├── internal.py              # Internal/container scanning
│   │   ├── network_probe.py         # Internal network + IMDS probing
│   │   ├── git_scanner.py           # Git history mining
│   │   ├── wayback.py               # Wayback Machine URL discovery
│   │   ├── cloud_storage.py         # S3/GCS/Azure blob enumeration
│   │   ├── resolver.py              # Bulk DNS resolution
│   │   └── shodan.py                # Shodan infrastructure mapping
│   │
│   ├── extract/                     # Extraction pipeline
│   │   ├── quick.py                 # Fast regex scanner
│   │   ├── decode.py                # Multi-layer decode chain
│   │   ├── ast.py                   # JavaScript AST parser
│   │   ├── objects.py               # Object/config extraction
│   │   ├── entropy.py               # Shannon entropy + FP detection
│   │   └── jwt_prescan.py           # JWT pre-extraction + decode
│   │
│   ├── correlate/                   # Correlation engine
│   │   ├── dedup.py                 # Candidate deduplication + merge
│   │   ├── pairing.py               # Credential pair detection
│   │   ├── confidence.py            # Multi-signal confidence scoring
│   │   └── ai_analyzer.py           # Claude AI contextual analysis
│   │
│   ├── verify/                      # Verification engines (24 verifiers)
│   │   ├── base.py                  # Base verifier class
│   │   ├── coordinator.py           # Routes findings to verifiers
│   │   ├── aws.py                   # AWS STS
│   │   ├── azure.py                 # Microsoft Azure
│   │   ├── gcp.py                   # Google Cloud
│   │   ├── github.py                # GitHub API
│   │   ├── heroku.py                # Heroku
│   │   ├── digitalocean.py          # DigitalOcean
│   │   ├── cloudflare.py            # Cloudflare
│   │   ├── slack.py                 # Slack
│   │   ├── discord.py               # Discord
│   │   ├── telegram.py              # Telegram
│   │   ├── twilio.py                # Twilio
│   │   ├── stripe.py                # Stripe
│   │   ├── sendgrid.py              # SendGrid
│   │   ├── openai.py                # OpenAI
│   │   ├── anthropic.py             # Anthropic
│   │   ├── shodan.py                # Shodan
│   │   ├── npm.py                   # NPM
│   │   ├── pypi.py                  # PyPI
│   │   ├── supabase.py              # Supabase
│   │   ├── mongodb.py               # MongoDB
│   │   ├── postgres.py              # PostgreSQL
│   │   ├── redis_verify.py          # Redis
│   │   ├── vault.py                 # HashiCorp Vault
│   │   └── jwt.py                   # JWT decode + validate
│   │
│   ├── rules/                       # Detection rules (8 YAML files)
│   │   ├── engine.py                # Rule matching engine
│   │   ├── loader.py                # YAML rule loader
│   │   ├── cloud.yaml               # Cloud provider patterns
│   │   ├── ai.yaml                  # AI/ML service patterns
│   │   ├── devtools.yaml            # DevOps tool patterns
│   │   ├── communication.yaml       # Communication service patterns
│   │   ├── payment.yaml             # Payment platform patterns
│   │   ├── database.yaml            # Database connection patterns
│   │   ├── vcs.yaml                 # VCS/registry patterns
│   │   └── cloud_services.yaml      # SaaS/CDN patterns
│   │
│   ├── output/                      # Output formats
│   │   ├── console.py               # Rich live dashboard
│   │   ├── sarif.py                 # SARIF format (CI/CD)
│   │   └── html_report.py           # HTML report generator
│   │
│   ├── api/                         # REST API [ENTERPRISE]
│   │   ├── server.py                # FastAPI/aiohttp server
│   │   └── webhooks.py              # Webhook notifications
│   │
│   ├── storage/                     # Persistence [ENTERPRISE]
│   │   └── database.py              # SQLite backend
│   │
│   ├── scheduler/                   # Scheduling [ENTERPRISE]
│   │   └── scheduler.py             # Cron-based scheduler
│   │
│   ├── observability/               # Monitoring [ENTERPRISE]
│   │   ├── logging.py               # Structured JSON logging
│   │   └── metrics.py               # Prometheus metrics
│   │
│   └── ui/                          # Terminal UI
│       ├── banners.py               # ASCII art banners
│       └── colors.py                # Color definitions
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
