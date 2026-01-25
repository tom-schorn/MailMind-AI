"""Claude AI integration for spam analysis."""

import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import anthropic

logger = logging.getLogger(__name__)


class SpamCategory(Enum):
    """Spam category types."""

    LEGITIMATE = "legitimate"
    PHISHING = "phishing"
    SCAM = "scam"
    MALWARE = "malware"
    ADULT = "adult"
    UNKNOWN = "unknown"


# Model ID mapping
MODELS = {
    "haiku": "claude-3-5-haiku-20241022",
    "sonnet": "claude-sonnet-4-20250514",
    "opus": "claude-opus-4-20250514",
}


@dataclass
class AnalysisResult:
    """Result from spam analysis step."""

    spam_score: float  # 0.0 = legitimate, 1.0 = definite spam
    reason: str
    is_certain: bool  # True if we can skip remaining steps
    category: SpamCategory = SpamCategory.UNKNOWN


class ClaudeAnalyzer:
    """Claude-based email spam analyzer."""

    def __init__(
        self,
        api_key: str,
        model: str = "haiku",
        sensitivity: int = 5,
        custom_prompt: Optional[str] = None,
    ):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = MODELS.get(model, MODELS["haiku"])
        self.sensitivity = sensitivity
        self.custom_prompt = custom_prompt

    def _analyze(self, system_prompt: str, user_content: str) -> AnalysisResult:
        """Run analysis with Claude and parse response."""
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=256,
                system=system_prompt,
                messages=[{"role": "user", "content": user_content}],
            )

            text = response.content[0].text
            return self._parse_response(text)

        except anthropic.APIError as e:
            logger.error(f"Claude API error: {e}")
            return AnalysisResult(
                spam_score=0.5,
                reason="Analysis failed due to API error",
                is_certain=False,
            )

    def _parse_response(self, text: str) -> AnalysisResult:
        """Parse Claude's JSON response."""
        try:
            # Find JSON in response
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(text[start:end])

                # Parse category
                cat_str = str(data.get("category", "unknown")).lower()
                try:
                    category = SpamCategory(cat_str)
                except ValueError:
                    category = SpamCategory.UNKNOWN

                return AnalysisResult(
                    spam_score=float(data.get("spam_score", 0.5)),
                    reason=str(data.get("reason", "Unknown")),
                    is_certain=bool(data.get("is_certain", False)),
                    category=category,
                )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse response: {e}")

        return AnalysisResult(
            spam_score=0.5,
            reason="Could not parse analysis result",
            is_certain=False,
            category=SpamCategory.UNKNOWN,
        )

    def _get_sensitivity_instruction(self) -> str:
        """Get sensitivity-based instruction text."""
        if self.sensitivity <= 3:
            return "Be VERY lenient. Only flag obvious, clear-cut spam. When in doubt, allow."
        elif self.sensitivity <= 6:
            return "Be balanced. Flag likely spam but avoid false positives."
        else:
            return "Be strict. Flag anything suspicious. Better safe than sorry."

    def analyze_subject(self, subject: str) -> AnalysisResult:
        """Analyze email subject for spam indicators."""
        if self.custom_prompt:
            system_prompt = self.custom_prompt
        else:
            system_prompt = f"""You are an email spam analyzer. Analyze ONLY the email subject line.
Sensitivity: {self.sensitivity}/10. {self._get_sensitivity_instruction()}

SPAM CATEGORIES:
- phishing: Fake account warnings, credential harvesting, urgent security alerts
- scam: Lottery wins, inheritance, crypto schemes, get-rich-quick
- malware: Download requests, attachment warnings, fake invoices
- adult: Explicit content, dating spam

LEGITIMATE (category: legitimate):
- Newsletters with company names
- Marketing from known brands
- Order confirmations, shipping updates
- Social media notifications
- Service notifications

Respond with JSON only:
{{"spam_score": 0.0-1.0, "category": "legitimate/phishing/scam/malware/adult", "reason": "brief explanation", "is_certain": true/false}}

is_certain=true ONLY for obvious spam (score >= 0.9)"""

        return self._analyze(system_prompt, f"Subject: {subject}")

    def analyze_sender(self, sender: str) -> AnalysisResult:
        """Analyze sender address for spam indicators."""
        if self.custom_prompt:
            system_prompt = self.custom_prompt
        else:
            system_prompt = f"""You are an email spam analyzer. Analyze ONLY the sender address.
Sensitivity: {self.sensitivity}/10. {self._get_sensitivity_instruction()}

SPAM INDICATORS (phishing category):
- Typosquatting: paypa1.com, amaz0n.com, g00gle.com, app1e.com
- Random strings: abc123xyz@domain.com
- Suspicious TLDs with random names: .xyz, .top, .click, .info
- Impersonation: security-amazon@gmail.com

LEGITIMATE (category: legitimate):
- Major companies: @apple.com, @google.com, @microsoft.com, @amazon.com
- Newsletter subdomains: @mail.*, @news.*, @newsletter.*, @info.*
- Known brands: patreon, freeletics, waipu, temu, kleinanzeigen, etc.
- Recognizable company domains

Respond with JSON only:
{{"spam_score": 0.0-1.0, "category": "legitimate/phishing/scam/malware/adult", "reason": "brief explanation", "is_certain": true/false}}

is_certain=true ONLY for obvious spam (score >= 0.9)"""

        return self._analyze(system_prompt, f"Sender: {sender}")

    def analyze_headers(self, headers: dict[str, str]) -> AnalysisResult:
        """Analyze email headers for security issues."""
        # Extract only relevant security headers
        security_info = []

        if "Authentication-Results" in headers:
            security_info.append(
                f"Auth-Results: {headers['Authentication-Results'][:500]}"
            )

        if "Received-SPF" in headers:
            security_info.append(f"SPF: {headers['Received-SPF'][:200]}")

        if "DKIM-Signature" in headers:
            security_info.append("DKIM: Present")
        else:
            security_info.append("DKIM: Missing")

        if "ARC-Authentication-Results" in headers:
            security_info.append(
                f"ARC: {headers['ARC-Authentication-Results'][:200]}"
            )

        header_text = "\n".join(security_info) if security_info else "No security headers found"

        if self.custom_prompt:
            system_prompt = self.custom_prompt
        else:
            system_prompt = f"""You are an email security analyzer. Analyze authentication headers.
Sensitivity: {self.sensitivity}/10. {self._get_sensitivity_instruction()}

CHECK FOR:
- SPF: pass (good), fail (bad), none (neutral)
- DKIM: valid (good), invalid (bad), missing (neutral for small senders)
- DMARC: pass (good), fail (bad)

IMPORTANT:
- Missing DKIM alone is NOT spam - many legitimate small senders don't use it
- SPF/DKIM/DMARC all failing together is suspicious (phishing category)
- Authentication failures from major companies = likely phishing

Respond with JSON only:
{{"spam_score": 0.0-1.0, "category": "legitimate/phishing/scam/malware/adult", "reason": "brief explanation", "is_certain": true/false}}

is_certain=true ONLY for clear forgery (score >= 0.9)"""

        return self._analyze(system_prompt, header_text)

    def analyze_content(self, body: str, subject: str) -> AnalysisResult:
        """Analyze email content for spam patterns."""
        # Limit body to avoid token overuse - privacy focused
        truncated_body = body[:1500] if len(body) > 1500 else body

        if self.custom_prompt:
            system_prompt = self.custom_prompt
        else:
            system_prompt = f"""You are an email spam analyzer. Analyze the email content.
Sensitivity: {self.sensitivity}/10. {self._get_sensitivity_instruction()}

SPAM CATEGORIES:
- phishing: Fake login pages, "verify your account", credential requests, mismatched URLs
- scam: Lottery/inheritance wins, crypto schemes, advance fee fraud, "you won", Nigerian prince
- malware: Suspicious attachments (.exe, .zip), download links, fake invoices, "open attached"
- adult: Explicit content, dating spam, adult services

RED FLAGS:
- Generic greetings ("Dear Customer", "Dear User")
- Urgency + threat ("Act now or lose access")
- Requests for passwords, SSN, bank details
- Mismatched sender vs content brand
- Poor grammar in supposedly professional emails
- Shortened URLs (bit.ly, tinyurl) to unknown destinations

LEGITIMATE (category: legitimate):
- Newsletters with unsubscribe links
- Marketing from identifiable brands
- Order/shipping confirmations
- Account notifications from known services
- Social media digests
- Promotional offers from real companies
- Urgency in legitimate contexts (flash sales, expiring offers)

NOTE: Marketing language, promotional content, and urgency are normal for legitimate businesses.

Respond with JSON only:
{{"spam_score": 0.0-1.0, "category": "legitimate/phishing/scam/malware/adult", "reason": "brief explanation", "is_certain": true/false}}"""

        content = f"Subject: {subject}\n\nBody:\n{truncated_body}"
        return self._analyze(system_prompt, content)
