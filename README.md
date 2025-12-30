# X-POSURE v1.0 → v2.0 (In Development)

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
  <strong>💀 Expose EVERYTHING about a target with a single click 💀</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0→2.0-orange?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/detection-66→1000+-red?style=for-the-badge" alt="Detection Types">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=for-the-badge" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License">
</p>

<p align="center">
  <strong>The most comprehensive domain-based credential harvester for offensive security</strong>
</p>

---

> **⚠️ CURRENT STATUS (v1.0):** X-POSURE currently detects **66 credential types**. We're expanding to **1000+ types** to truly "expose everything" about a target. See [EXPOSURE_EXPANSION_PLAN.md](EXPOSURE_EXPANSION_PLAN.md) for the 12-week roadmap.
>
> **Current Coverage:** 6.4% vs industry-leading tools | **Target Coverage:** 97%+
>
> **What Works Now:** Web discovery, advanced correlation, active verification (5 providers)
> **Coming Soon:** 15x more credential types, 14x more verifiers, comprehensive coverage

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

# Run a scan
python -m xposure example.com

# Save results to JSON
python -m xposure example.com -o results.json
```

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
**Current: 66 credential types | Target: 1000+ types**

| Category | Current | Planned | Key Additions |
|----------|---------|---------|---------------|
| ☁️ **Cloud Infrastructure** | 15 | 150 | +Cloudflare, Vercel, Netlify, IBM Cloud, Oracle, Render, Railway, Fly.io |
| 🤖 **AI/ML Services** | 16 | 60 | +Google AI, xAI, ElevenLabs, DeepSeek, Groq, Perplexity, Together AI |
| 📦 **Version Control** | 10 | 30 | (Good coverage - minor additions) |
| 💬 **Communication** | 13 | 50 | +Microsoft Teams, Webex, RingCentral, MessageBird, Customer.io |
| 💳 **Payment Processing** | 7 | 30 | +Checkout.com, Adyen, Paddle, LemonSqueezy, Chargebee |
| 🗄️ **Databases** | 6 | 40 | +Elasticsearch, InfluxDB, Cassandra, Neo4j, DynamoDB, CosmosDB |
| 🔧 **CI/CD & DevOps** | 1 | 100 | +CircleCI, Jenkins, BuildKite, Docker, Kubernetes, ArgoCD |
| 📊 **Monitoring** | 0 | 40 | +Datadog, New Relic, Sentry, Grafana, Splunk, Honeycomb |
| 🔐 **Secret Management** | 0 | 20 | +HashiCorp Vault, Doppler, 1Password, Infisical |
| 💼 **SaaS/Productivity** | 0 | 200 | +Notion, Airtable, Jira, Linear, HubSpot, Salesforce |
| 🏪 **CMS/E-commerce** | 0 | 50 | +Shopify, WooCommerce, Contentful, Strapi, Sanity |
| 🔒 **Security/Compliance** | 0 | 40 | +Wiz, Snyk, Qualys, Tenable, Detectify |
| 🎯 **Analytics** | 0 | 50 | +Mixpanel, Amplitude, Segment, PostHog, FullStory |
| 🌐 **Others** | 0 | 300+ | Social, Finance, HR, Blockchain, Media, Regional APIs |

**Current Features:**
- Context-aware matching (requires surrounding keywords)
- Severity levels (CRITICAL to INFO)
- Exclusion patterns for false positives
- Metadata: provider docs, remediation steps
- False positive detection with Shannon entropy filtering

**Coming in v2.0:**
- 15x more detection rules (66 → 1000+)
- Advanced pattern matching with trie-based optimization
- Machine learning-enhanced false positive reduction
- Community-contributed rule marketplace

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
**Current: 5 active verifiers | Target: 70+ verifiers**

**Passive Verification** (format checks):
- AWS access key structure validation
- GitHub token prefix detection (ghp_, gho_, ghu_, ghs_, ghr_)
- Stripe key environment detection (live vs test)
- OpenAI key type identification (project vs user)
- Generic format validation for all credential types

**Active Verification - Current (5 providers):**

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

**Coming in v2.0 - Additional Verifiers (+65):**

**Phase 1 (Week 1-2):** Essential Cloud & DevOps
- GCP (tokeninfo), Azure (Microsoft Graph), DigitalOcean, Cloudflare, Vercel, Netlify
- Datadog, Sentry, New Relic, GitLab, Bitbucket, Docker Hub
- CircleCI, Terraform Cloud, MongoDB Atlas, Supabase

**Phase 2 (Week 3-4):** Common SaaS
- Notion, Airtable, Jira, Linear, HubSpot, Anthropic
- Google AI, xAI, ElevenLabs, SendGrid, Twilio, Microsoft Teams

**Phase 3 (Week 5-6):** Specialized Services
- Shopify, WooCommerce, Contentful, Mixpanel, Amplitude
- Auth0, Okta, HashiCorp Vault, Grafana

**Phase 4 (Week 7+):** Long-tail & Generic
- 30+ additional service-specific verifiers
- Generic HTTP verifier framework for 500+ services

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

### ✅ Completed (v1.0) - Foundation
- [x] **Core Engine**: Scaffolding, CLI, state persistence, async architecture
- [x] **Discovery Pipeline**: Subdomains (crt.sh + DNS), paths, JavaScript harvesting, config files, source maps
- [x] **Extraction Pipeline**: Regex scanner, decode chains, AST parsing, object extraction
- [x] **Rules Engine**: YAML-based system with 66 credential types
- [x] **Correlation Module**: Deduplication, pairing, confidence scoring, content graph
- [x] **Verification System**: 5 active verifiers (AWS, GitHub, Slack, Stripe, OpenAI)
- [x] **False Positive Detection**: Shannon entropy filtering, context analysis

### 🚧 v2.0 Expansion (12-Week Plan) - "Expose Everything"

See [EXPOSURE_EXPANSION_PLAN.md](EXPOSURE_EXPANSION_PLAN.md) for detailed implementation strategy.

**Week 1: Critical Foundation (→166 types, 16% coverage)**
- [ ] Fix `pyjsparser` dependency (blocker)
- [ ] Add Tier 1 critical types (+100): Cloudflare, Vercel, Datadog, monitoring, CI/CD
- [ ] Add 15 essential verifiers: GCP, Azure, DigitalOcean, Datadog, Sentry
- [ ] Create rule generator automation
- [ ] Setup comprehensive test suite

**Week 2-3: Essential Services (→316 types, 31% coverage)**
- [ ] Add Tier 2 types (+150): Microsoft Teams, Notion, Jira, Shopify, Auth0
- [ ] Add 25 verifiers: Notion, Airtable, HubSpot, Anthropic, Google AI
- [ ] Implement performance optimizations (trie-based matching)
- [ ] Add caching layer

**Week 4-6: Important Coverage (→516 types, 50% coverage)**
- [ ] Add Tier 3 types (+200): Wiz, Snyk, Mixpanel, Analytics, Marketing tools
- [ ] Add 30 verifiers: Shopify, Mixpanel, Auth0
- [ ] Generic HTTP verifier framework
- [ ] Automated false positive testing

**Week 7-9: Useful Additions (→716 types, 69% coverage)**
- [ ] Add Tier 4 types (+200): Finance, HR, Social, Blockchain, Media
- [ ] Performance tuning and optimization
- [ ] Live dashboard with Rich
- [ ] Comprehensive documentation

**Week 10-12: Excellence (→1000+ types, 97%+ coverage)**
- [ ] Add Tier 5 long-tail types (+300+): Niche APIs, regional services
- [ ] Final polish and optimization
- [ ] Benchmark testing and publication
- [ ] Community contribution framework

### 🎯 v2.0 Success Metrics
- ✅ 1000+ credential types (15x current)
- ✅ 70+ active verifiers (14x current)
- ✅ <5% false positive rate
- ✅ <5min full domain scan
- ✅ 97%+ coverage vs industry leaders
- ✅ Production-ready for enterprise targets

### 🔮 v3.0 Vision (Future)
- [ ] Git repository scanning (compete with TruffleHog fully)
- [ ] Filesystem scanning for local assessments
- [ ] S3/GCS/Azure Blob bucket enumeration
- [ ] CI/CD pipeline integrations (GitHub Actions, GitLab CI)
- [ ] Pre-commit/pre-receive hooks
- [ ] Enterprise SaaS platform
- [ ] API marketplace for custom detectors

---

## 📋 Planning Documents

Comprehensive analysis and expansion strategy documents:

1. **[STATUS_REVIEW.md](STATUS_REVIEW.md)** - Current state analysis
   - Detailed comparison: X-POSURE vs TruffleHog
   - Gap analysis (66 vs 1036 credential types)
   - Technical assessment of strengths and weaknesses

2. **[EXPOSURE_EXPANSION_PLAN.md](EXPOSURE_EXPANSION_PLAN.md)** - 12-week implementation plan
   - Tier-by-tier expansion strategy (Critical → Long-tail)
   - Detailed timelines and resource requirements
   - Technical implementation details
   - Verification expansion strategy
   - Performance optimization plans

3. **[EXECUTIVE_SUMMARY.md](EXECUTIVE_SUMMARY.md)** - Decision framework
   - Two paths analysis (Niche vs Comprehensive)
   - Success metrics and milestones
   - Risk mitigation strategies
   - Immediate next steps

---

## 🚨 Known Issues & Blockers

### Critical Blockers
- **`pyjsparser` dependency fails to install** - Build error on pip install
  - Impact: JavaScript AST parsing disabled
  - Workaround: Regex-only extraction (functional but less effective)
  - Fix planned: Switch to `esprima-python` or `slimit` (Week 1)

### High Priority
- **Limited test coverage** - Only 4 test files
  - Impact: Risk of regressions during expansion
  - Fix planned: Comprehensive test suite (Week 1)

- **Performance with large files** - Scans can be slow on 1MB+ JavaScript files
  - Impact: Long scan times for some targets
  - Fix planned: Smart sampling and caching (Week 2-3)

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
- Rich (terminal UI)

**Inspired by:** TruffleHog, Nuclei, and the offensive security community

**Special thanks to the security community for inspiration and feedback.**

---

## 📞 Contact

- **GitHub**: [@SnailSploit](https://github.com/SnailSploit)
- **Project**: [X-Posure](https://github.com/SnailSploit/X-Posure)
- **Issues**: [GitHub Issues](https://github.com/SnailSploit/X-Posure/issues)
- **Discussions**: [GitHub Discussions](https://github.com/SnailSploit/X-Posure/discussions)

---

## 🎯 The Vision

**X-POSURE** exists to solve one problem: **expose EVERYTHING about a target with a single click.**

Not 6.4%. Not "good enough." **EVERYTHING.**

- Every exposed credential across all major services
- Every misconfigured API key in every JavaScript file
- Every forgotten secret in every config file
- Every leaked token in every subdomain

**v1.0 laid the foundation. v2.0 delivers the vision.**

12 weeks. 1000+ credential types. 70+ verifiers. 97%+ coverage.

The shit your DevOps forgot? **We'll find it all.** 💀

---

<p align="center">
  <strong>💀 Expose EVERYTHING. Leave nothing hidden. 💀</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/current-66_types-orange?style=flat-square" alt="Current">
  <img src="https://img.shields.io/badge/target-1000+_types-red?style=flat-square" alt="Target">
  <img src="https://img.shields.io/badge/coverage-6.4%→97%+-green?style=flat-square" alt="Coverage">
</p>

<p align="center">
  Made with ☕ and 🔥 by SnailSploit
</p>
