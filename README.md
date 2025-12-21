# X-POSURE v1.0

```
 ██╗  ██╗       ██████╗  ██████╗ ███████╗██╗   ██╗██████╗ ███████╗
 ╚██╗██╔╝       ██╔══██╗██╔═══██╗██╔════╝██║   ██║██╔══██╗██╔════╝
  ╚███╔╝  █████╗██████╔╝██║   ██║███████╗██║   ██║██████╔╝█████╗  
  ██╔██╗  ╚════╝██╔═══╝ ██║   ██║╚════██║██║   ██║██╔══██╗██╔══╝  
 ██╔╝ ██╗       ██║     ╚██████╔╝███████║╚██████╔╝██║  ██║███████╗
 ╚═╝  ╚═╝       ╚═╝      ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝

 V.1.0.0 // For Shit Your DevOps Forgot.
 by SnailSploit <3
```

<p align="center">
  <strong>💀 The shit your DevOps forgot. 💀</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-red?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=for-the-badge" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/status-active-success?style=for-the-badge" alt="Status">
</p>

<p align="center">
  <strong>Domain-based credential harvester for red team operations and bug bounty hunting</strong>
</p>

---

## 🎯 What is X-POSURE?

**X-POSURE** is a next-generation credential harvester that discovers, extracts, correlates, and verifies exposed secrets across your target's attack surface. Built for offensive security professionals who need **accurate intelligence, not noise**.

### Why X-POSURE?

- 🔍 **Comprehensive Discovery**: Subdomains, paths, JavaScript files - finds the attack surface
- 🧠 **Intelligent Extraction**: AST parsing, decode chains, entropy filtering - not just regex
- 🔗 **Smart Correlation**: Pairs credentials, deduplicates across sources, scores confidence
- ✅ **Active Verification**: Actually checks if credentials work and who they belong to
- 📊 **Actionable Intelligence**: Identity, permissions, blast radius, pivot opportunities

**Stop collecting garbage. Start finding gold.**

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/SnailSploit/X-Posure.git
cd X-Posure

# Option 1: Install dependencies with requirements.txt
pip install -r requirements.txt

# Option 2: Install as package (recommended)
pip install -e .

# Explore flags
python -m xposure --help

# Run a scan
python -m xposure example.com

# Save results to JSON
python -m xposure example.com -o results.json
```

### 🎛️ Live Dashboard (Mr. Robot mode)

The default run launches a neon console dashboard inspired by *Mr. Robot*:

- Glitchy banner + status ticker
- Live telemetry (recon counts, candidate totals, verification results)
- Phase-aware updates as the engine moves from discovery → extraction → correlation → verification

Prefer silent mode? Add `-q/--quiet` to stream minimal output, or `--no-verify` if you only want passive checks.

---

## ✨ Features

### 🔭 Discovery Engine
- **Certificate Transparency**: Query crt.sh for subdomain discovery
- **DNS Bruteforce**: Common subdomain wordlist with async verification
- **Path Discovery**: robots.txt, sitemap.xml, common sensitive paths, API endpoints
- **JavaScript Harvesting**: External scripts, inline code, ES6 imports, webpack bundles
- **Streaming Architecture**: Results as they're found, no batch processing

### 🎣 Extraction Pipeline
- **Quick Scanner**: 20+ regex patterns with Shannon entropy filtering
- **Decode Chain**: Recursive base64/hex/URL/unicode/ROT13 decoding (configurable depth)
- **JavaScript AST Parser**: pyjsparser with intelligent fallback for obfuscated code
- **Object Extractor**: JSON objects, key-value pairs, connection strings, credential pairing
- **Multi-layered**: Scans original content + all decoded variants

### 🎯 Rules Engine
**64+ Detection Rules** across 6 categories:

| Category | Rules | Examples |
|----------|-------|----------|
| ☁️ **Cloud** | 15 | AWS (keys, secrets, tokens), GCP, Azure, DigitalOcean, Terraform |
| 🤖 **AI/ML** | 16 | OpenAI, Anthropic, Cohere, HuggingFace, Stability AI, Pinecone |
| 📦 **Version Control** | 10 | GitHub (PATs, OAuth, Apps), GitLab, Bitbucket, Azure DevOps |
| 💬 **Communication** | 13 | Slack, Discord, Twilio, SendGrid, Mailgun, Telegram, Zendesk |
| 💳 **Payment** | 7 | Stripe, PayPal, Square, Braintree |
| 🗄️ **Database** | 6 | MongoDB, PostgreSQL, MySQL, Redis, Firebase, Supabase |

**Features:**
- Context-aware matching (requires surrounding keywords)
- Severity levels (CRITICAL to INFO)
- Exclusion patterns for false positives
- Metadata: provider docs, remediation steps

### 🧩 Correlation Module
- **Deduplication**: SHA256 hash-based with multi-source evidence tracking
- **Credential Pairing**: Automatically pairs AWS key+secret, Azure client_id+secret, etc.
- **Confidence Scoring**: 6-factor algorithm
  - Entropy analysis (Shannon entropy thresholds)
  - Multi-source evidence (same cred from multiple locations = higher confidence)
  - Context quality (surrounding keywords and patterns)
  - Credential pairing (+15% boost for paired creds)
  - Severity weighting (CRITICAL findings weighted higher)
  - Provider trust (AWS/GitHub/Stripe rated higher than Telegram)
- **Content Graph**: Tracks discovery chains (domain → subdomain → JS file → finding)

### ✅ Verification Engine
**Passive Verification** (format checks):
- AWS access key structure validation
- GitHub token prefix detection (ghp_, gho_, ghu_, ghs_, ghr_)
- Stripe key environment detection (live vs test)
- OpenAI key type identification (project vs user)

**Active Verification** (5 providers):

#### 🔶 AWS Verifier
- **Method**: STS GetCallerIdentity API
- **Auth**: AWS Signature V4 (implemented from scratch)
- **Discovers**: IAM user, role, root account, assumed role
- **Blast Radius**: root=CRITICAL, admin=HIGH, user=MEDIUM/LOW
- **Requires**: Paired access key + secret key

#### 🐙 GitHub Verifier
- **Method**: /user API endpoint
- **Discovers**: Username, email, account type, OAuth scopes
- **Permissions**: Extracted from X-OAuth-Scopes header
- **Blast Radius**: Based on repo/org access level
- **Pivot**: Webhooks (RCE potential), Actions secrets, org settings

#### 💬 Slack Verifier
- **Method**: auth.test API
- **Discovers**: Workspace, team, bot vs user token
- **Blast Radius**: Admin/enterprise=CRITICAL, files/channels=HIGH
- **Supports**: Bot tokens, user tokens, webhooks

#### 💳 Stripe Verifier
- **Method**: /v1/account API
- **Discovers**: Business name, account ID, charges enabled
- **Environment**: Live vs test mode detection
- **Blast Radius**: live+charges=CRITICAL

#### 🤖 OpenAI Verifier
- **Method**: /v1/models API
- **Discovers**: Available models (GPT-4, DALL-E, etc.)
- **Key Type**: Project vs user key detection
- **Blast Radius**: Cost-based (GPT-4/DALL-E=HIGH)

**Verification Results Include:**
- ✓ Status (verified, likely_valid, invalid, error)
- ✓ Identity (who owns the credential)
- ✓ Permissions (what it can do)
- ✓ Blast Radius (CRITICAL → INFO)
- ✓ Environment (production, staging, test)
- ✓ Pivot Opportunities (where attackers can go)

---

## 📊 Example Output

```
 ██╗  ██╗       ██████╗  ██████╗ ███████╗██╗   ██╗██████╗ ███████╗
 ╚██╗██╔╝       ██╔══██╗██╔═══██╗██╔════╝██║   ██║██╔══██╗██╔════╝
  ╚███╔╝  █████╗██████╔╝██║   ██║███████╗██║   ██║██████╔╝█████╗  
  ██╔██╗  ╚════╝██╔═══╝ ██║   ██║╚════██║██║   ██║██╔══██╗██╔══╝  
 ██╔╝ ██╗       ██║     ╚██████╔╝███████║╚██████╔╝██║  ██║███████╗
 ╚═╝  ╚═╝       ╚═╝      ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝

 V.1.0.0 // For Shit Your DevOps Forgot.
 by SnailSploit <3

[x-posure] scanning example.com...
[x-posure] target: example.com
[x-posure] scan_id: example_com_20251220_184530

[discovery] starting reconnaissance...
[subdomain] api.example.com
[subdomain] cdn.example.com
[subdomain] staging.example.com
[path] https://example.com/robots.txt
[path] https://example.com/.env
[js] https://cdn.example.com/bundle.js
[discovery] found 12 subdomains
[discovery] found 8 js files

[extraction] analyzing content...
[extract] found 15 candidates in https://example.com/.env
[candidate] aws_access_key: AKIAIOSFODNN7EXAM...
[candidate] aws_secret_key: wJalrXUtnFEMI/K7M...
[decoded] found 3 in base64
[extraction] found 47 total candidates
[extraction] decoded 12 encoded blobs

[correlation] analyzing relationships...
[dedup] 47 candidates -> 12 unique findings
[pairing] found 3 credential pairs
[correlation] 12 unique findings
[correlation] 4 from multiple sources
[correlation] avg confidence: 0.78
[correlation] graph nodes: 25, edges: 38

[verification] validating credentials...
[verification] verified 12 findings
[verification] 8 valid credentials
[verification] 2 invalid credentials
[verification] 2 verification errors

[!] 5 HIGH-VALUE credentials found:
  [aws_access_key] IAM User: admin-deploy (critical)
  [github_token] SnailSploit (admin) (high)
  [stripe_secret_key] Acme Corp (sk_live_...) (critical)
  [openai_key] OpenAI Project Key (high)
  [slack_token] Bot: deploy-bot in Acme Workspace (high)

======================================================================
SCAN COMPLETE
======================================================================
Duration: 43.2s

Findings:
  Verified:    8
  Unverified:  2
  Invalid:     2
  Errors:      0
  Total:       12
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         X-POSURE                            │
│                         Pipeline                            │
└─────────────────────────────────────────────────────────────┘

Input: example.com
    │
    ▼
┌───────────────┐
│  DISCOVERY    │  → Subdomains (crt.sh, DNS)
│               │  → Paths (robots.txt, sitemap, common)
│               │  → JavaScript Files (script tags, inline, imports)
└───────┬───────┘
        │  [12 subdomains, 8 JS files, 25 paths]
        ▼
┌───────────────┐
│  EXTRACTION   │  → Quick Scanner (regex + entropy)
│               │  → Decode Chain (base64, hex, URL, etc.)
│               │  → AST Parser (JavaScript object extraction)
│               │  → Object Extractor (JSON, key-value, connections)
└───────┬───────┘
        │  [47 credential candidates]
        ▼
┌───────────────┐
│  RULES        │  → 64+ YAML rules
│  ENGINE       │  → Context-aware matching
│               │  → Severity classification
│               │  → Metadata enrichment
└───────┬───────┘
        │  [47 matched candidates]
        ▼
┌───────────────┐
│  CORRELATION  │  → Deduplication (SHA256 hash)
│               │  → Credential Pairing (AWS key+secret)
│               │  → Confidence Scoring (6 factors)
│               │  → Content Graph (evidence chains)
└───────┬───────┘
        │  [12 unique findings, 3 pairs, avg confidence 0.78]
        ▼
┌───────────────┐
│  VERIFICATION │  → Passive (format checks)
│               │  → Active (AWS, GitHub, Slack, Stripe, OpenAI)
│               │  → Identity Discovery
│               │  → Blast Radius Assessment
└───────┬───────┘
        │  [8 verified, 2 invalid, 2 errors]
        ▼
┌───────────────┐
│    OUTPUT     │  → JSON Export
│               │  → Stats Summary
│               │  → High-Value Alerts
└───────────────┘
```

---

## 📂 Project Structure

```
X-Posure/
├── xposure/
│   ├── __init__.py
│   ├── __version__.py         # Version info
│   ├── cli.py                  # Click CLI interface
│   ├── config.py               # Configuration management
│   ├── state.py                # Scan state persistence
│   │
│   ├── core/
│   │   ├── engine.py           # Main scanning engine
│   │   ├── models.py           # Data models (Finding, Candidate, Source)
│   │   └── graph.py            # Content relationship graph
│   │
│   ├── discover/
│   │   ├── base.py             # Base discoverer class
│   │   ├── subdomains.py       # Subdomain discovery (crt.sh, DNS)
│   │   ├── paths.py            # Path discovery (robots, sitemap)
│   │   └── js.py               # JavaScript file harvesting
│   │
│   ├── extract/
│   │   ├── quick.py            # Quick regex scanner
│   │   ├── decode.py           # Recursive decode chain
│   │   ├── ast.py              # JavaScript AST parser
│   │   └── objects.py          # Object extraction
│   │
│   ├── rules/
│   │   ├── loader.py           # YAML rule loader
│   │   ├── engine.py           # Rule matching engine
│   │   ├── cloud.yaml          # Cloud provider rules (15)
│   │   ├── ai.yaml             # AI/ML service rules (16)
│   │   ├── vcs.yaml            # Version control rules (10)
│   │   ├── communication.yaml  # Communication rules (13)
│   │   ├── payment.yaml        # Payment processor rules (7)
│   │   └── database.yaml       # Database rules (6)
│   │
│   ├── correlate/
│   │   ├── dedup.py            # Deduplication engine
│   │   ├── pairing.py          # Credential pairing
│   │   ├── confidence.py       # Confidence scoring
│   │   └── __init__.py
│   │
│   ├── verify/
│   │   ├── base.py             # Base verifier + passive checks
│   │   ├── coordinator.py      # Verification coordinator
│   │   ├── aws.py              # AWS STS verifier
│   │   ├── github.py           # GitHub API verifier
│   │   ├── slack.py            # Slack API verifier
│   │   ├── stripe.py           # Stripe API verifier
│   │   ├── openai.py           # OpenAI API verifier
│   │   └── __init__.py
│   │
│   └── ui/
│       ├── banners.py          # ASCII art banners
│       └── colors.py           # Terminal colors
│
├── test_correlation.py         # Correlation module tests
├── test_extraction.py          # Extraction pipeline tests
├── test_rules.py               # Rules engine tests
├── test_verification.py        # Verification module tests
├── README.md                   # This file
├── LICENSE                     # MIT License
├── requirements.txt            # Dependencies
└── pyproject.toml              # Package configuration
```

---

## 🎮 Usage

### Basic Commands

```bash
# Scan a domain
python -m xposure example.com

# Save results to JSON
python -m xposure example.com -o results.json

# Quiet mode (no live output)
python -m xposure example.com --quiet

# Skip verification (faster, passive only)
python -m xposure example.com --no-verify

# Show version
python -m xposure --version
```

### Advanced Usage

```bash
# With GitHub token for dorking (future feature)
python -m xposure example.com -g ghp_YOUR_TOKEN_HERE

# Combine options
python -m xposure target.com -o findings.json --quiet
```

### Environment Variables

```bash
export GITHUB_TOKEN=ghp_your_token_here
export XPOSURE_OUTPUT=/path/to/output
export XPOSURE_QUIET=true
```

---

## 🧪 Testing

Run the test suites:

```bash
# Test correlation module
python test_correlation.py

# Test verification module
python test_verification.py

# Test rules engine
python test_rules.py

# Test extraction pipeline
python test_extraction.py
```

**Test Coverage:**
- ✅ Deduplication with multi-source evidence
- ✅ Credential pairing (AWS key+secret)
- ✅ Confidence scoring (6 factors)
- ✅ Content relationship graph
- ✅ Passive verification (format checks)
- ✅ Verifier routing logic
- ✅ AWS Signature V4 generation
- ✅ GitHub token type detection
- ✅ Quick regex scanner
- ✅ Decode chain (base64, hex, URL, unicode)
- ✅ JavaScript AST parsing
- ✅ Object extraction (JSON, connection strings)
- ✅ Rules loading and matching (64 rules)

---

## 📈 Development Roadmap

### ✅ Completed (v1.0)
- [x] **Session 1**: Core scaffolding, CLI, state persistence
- [x] **Session 2**: Discovery modules (subdomains, paths, JS)
- [x] **Session 3**: Extraction pipeline (regex, decode, AST, objects)
- [x] **Session 4**: Rules engine (YAML loader, matcher, 64+ rules)
- [x] **Session 5**: Correlation (pairing, dedup, confidence scoring, graph)
- [x] **Session 6**: Verification (AWS, GitHub, Slack, Stripe, OpenAI)

### 🚧 Planned
- [ ] **Session 7**: Live dashboard with Rich
- [ ] **Session 8**: GitHub dorking + S3 bucket enumeration
- [ ] **Session 9**: Additional verifiers (GCP, Azure, Anthropic)
- [ ] **Session 10**: Polish, comprehensive tests, packaging

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests.

### Development Setup

```bash
# Clone and install in dev mode
git clone https://github.com/SnailSploit/X-Posure.git
cd X-Posure
pip install -e .

# Run tests
python test_correlation.py
python test_verification.py
```

---

## ⚖️ Legal Disclaimer

**X-POSURE is designed for authorized security testing and bug bounty hunting only.**

- ✅ **LEGAL**: Testing your own systems
- ✅ **LEGAL**: Bug bounty programs with permission
- ✅ **LEGAL**: Authorized penetration testing engagements
- ❌ **ILLEGAL**: Unauthorized access to systems you don't own
- ❌ **ILLEGAL**: Credential harvesting without permission

**You are responsible for ensuring you have permission before using this tool.**

The authors assume no liability and are not responsible for any misuse or damage caused by this tool.

---

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Credits

**Created by SnailSploit**

Built with:
- Python 3.10+
- aiohttp (async HTTP)
- Click (CLI framework)
- PyYAML (rule parsing)
- aiodns (async DNS)
- pyjsparser (JavaScript AST)

**Special thanks to the security community for inspiration and feedback.**

---

## 📞 Contact

- **GitHub**: [@SnailSploit](https://github.com/SnailSploit)
- **Project**: [X-Posure](https://github.com/SnailSploit/X-Posure)

---

<p align="center">
  <strong>💀 Find the shit your DevOps forgot. 💀</strong>
</p>

<p align="center">
  Made with ☕ and 🔥 by SnailSploit
</p>
