"""Anthropic Claude integration — AI-powered finding analysis."""

from dataclasses import dataclass, field
from typing import Optional

from ..config import Config
from ..core.models import Finding, Severity


@dataclass
class AIAnalysis:
    """AI-generated analysis of scan findings + infrastructure."""
    risk_summary: str = ""
    critical_findings: list[dict] = field(default_factory=list)
    attack_chains: list[dict] = field(default_factory=list)
    remediation_priorities: list[dict] = field(default_factory=list)
    infrastructure_risks: list[dict] = field(default_factory=list)
    overall_risk_score: float = 0.0  # 0-10
    raw_response: str = ""
    model_used: str = ""
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "risk_summary": self.risk_summary,
            "critical_findings": self.critical_findings,
            "attack_chains": self.attack_chains,
            "remediation_priorities": self.remediation_priorities,
            "infrastructure_risks": self.infrastructure_risks,
            "overall_risk_score": self.overall_risk_score,
            "model_used": self.model_used,
            "error": self.error,
        }


class AnthropicAnalyzer:
    """Use Anthropic Claude API to analyze findings and infrastructure."""

    MODEL = "claude-sonnet-4-6"

    def __init__(self, config: Config, api_key: str):
        self.config = config
        self.api_key = api_key

    async def analyze(
        self,
        findings: list[Finding],
        infra_data: Optional[dict] = None,
        dns_data: Optional[dict] = None,
    ) -> AIAnalysis:
        """Send findings + infra to Claude for analysis.

        Args:
            findings: List of X-POSURE findings.
            infra_data: Shodan results (ip -> ShodanHostInfo.to_dict()).
            dns_data: DNS resolution results (domain -> ResolvedHost.to_dict()).

        Returns:
            AIAnalysis with risk assessment and recommendations.
        """
        try:
            import anthropic
        except ImportError:
            return AIAnalysis(error="anthropic package not installed (pip install anthropic)")

        prompt = self._build_prompt(findings, infra_data, dns_data)

        try:
            client = anthropic.Anthropic(api_key=self.api_key)
            message = client.messages.create(
                model=self.MODEL,
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}],
                system=(
                    "You are an expert security analyst reviewing automated scan results "
                    "from X-POSURE, an exposed credential scanner. Analyze the findings "
                    "and infrastructure data to provide actionable security intelligence. "
                    "Focus on real risk: what can an attacker actually do with these findings? "
                    "Respond ONLY in valid JSON matching this schema:\n"
                    "{\n"
                    '  "risk_summary": "2-3 sentence executive summary",\n'
                    '  "overall_risk_score": <0-10 float>,\n'
                    '  "critical_findings": [{"finding": "...", "why_critical": "...", "exploit_scenario": "..."}],\n'
                    '  "attack_chains": [{"chain": "step1 -> step2 -> step3", "impact": "...", "likelihood": "high/medium/low"}],\n'
                    '  "infrastructure_risks": [{"risk": "...", "affected_ips": [...], "recommendation": "..."}],\n'
                    '  "remediation_priorities": [{"priority": 1, "action": "...", "finding_ids": [...], "urgency": "immediate/short-term/long-term"}]\n'
                    "}"
                ),
            )

            raw = message.content[0].text
            return self._parse_response(raw)

        except anthropic.AuthenticationError:
            return AIAnalysis(error="invalid Anthropic API key")
        except anthropic.RateLimitError:
            return AIAnalysis(error="Anthropic rate limit hit")
        except Exception as e:
            return AIAnalysis(error=f"Anthropic API error: {e}")

    def _build_prompt(
        self,
        findings: list[Finding],
        infra_data: Optional[dict],
        dns_data: Optional[dict],
    ) -> str:
        """Build the analysis prompt from scan data."""
        sections = []

        # Target info
        sections.append(f"## Target\n{self.config.target}\n")

        # Findings
        if findings:
            sections.append("## Exposed Credentials Found")
            for f in findings[:50]:  # Cap to avoid token overflow
                status = f.status.value if hasattr(f.status, 'value') else str(f.status)
                severity = f.blast_radius.value if hasattr(f.blast_radius, 'value') else str(f.blast_radius)
                sources_str = ", ".join(s.url for s in f.sources[:3])

                lines = [
                    f"- **[{f.credential_type}]** ID: {f.id}",
                    f"  Status: {status} | Severity: {severity} | Confidence: {f.confidence:.0%}",
                    f"  Masked value: {f.masked_value}",
                    f"  Sources: {sources_str}",
                ]
                if f.identity:
                    lines.append(f"  Identity: {f.identity}")
                if f.permissions:
                    lines.append(f"  Permissions: {', '.join(f.permissions[:10])}")
                if f.environment:
                    lines.append(f"  Environment: {f.environment}")
                if f.can_pivot_to:
                    lines.append(f"  Can pivot to: {', '.join(f.can_pivot_to[:5])}")
                sections.append("\n".join(lines))
        else:
            sections.append("## Exposed Credentials Found\nNone found.\n")

        # Infrastructure data
        if infra_data:
            sections.append("## Infrastructure (Shodan)")
            for ip, info in list(infra_data.items())[:20]:
                if isinstance(info, dict):
                    data = info
                else:
                    data = info.to_dict() if hasattr(info, 'to_dict') else {}

                lines = [f"- **{ip}**"]
                if data.get("hostnames"):
                    lines.append(f"  Hostnames: {', '.join(data['hostnames'][:5])}")
                if data.get("ports"):
                    lines.append(f"  Open ports: {', '.join(str(p) for p in data['ports'][:20])}")
                if data.get("os"):
                    lines.append(f"  OS: {data['os']}")
                if data.get("organization"):
                    lines.append(f"  Org: {data['organization']}")
                if data.get("vulns"):
                    lines.append(f"  CVEs: {', '.join(data['vulns'][:10])}")
                sections.append("\n".join(lines))

        # DNS data
        if dns_data:
            sections.append("## DNS Resolution")
            for domain, info in list(dns_data.items())[:20]:
                if isinstance(info, dict):
                    data = info
                else:
                    data = info.to_dict() if hasattr(info, 'to_dict') else {}
                ips = data.get("ips", [])
                if ips:
                    sections.append(f"- {domain} -> {', '.join(ips)}")

        sections.append(
            "\n## Instructions\n"
            "Analyze these findings. Identify which exposed credentials pose the "
            "highest real-world risk. Look for attack chains (e.g., AWS key on "
            "server with open ports = full cloud compromise). Prioritize remediation "
            "by actual exploitability, not just severity labels. Return JSON only."
        )

        return "\n\n".join(sections)

    def _parse_response(self, raw: str) -> AIAnalysis:
        """Parse Claude's JSON response into AIAnalysis."""
        import json

        analysis = AIAnalysis(raw_response=raw, model_used=self.MODEL)

        # Strip markdown code fences if present
        text = raw.strip()
        if text.startswith("```"):
            # Remove first line (```json) and last line (```)
            lines = text.split("\n")
            text = "\n".join(lines[1:-1])

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Try to find JSON object in the response
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    data = json.loads(text[start:end])
                except json.JSONDecodeError:
                    analysis.risk_summary = raw[:500]
                    return analysis
            else:
                analysis.risk_summary = raw[:500]
                return analysis

        analysis.risk_summary = data.get("risk_summary", "")
        analysis.overall_risk_score = float(data.get("overall_risk_score", 0))
        analysis.critical_findings = data.get("critical_findings", [])
        analysis.attack_chains = data.get("attack_chains", [])
        analysis.infrastructure_risks = data.get("infrastructure_risks", [])
        analysis.remediation_priorities = data.get("remediation_priorities", [])

        return analysis
