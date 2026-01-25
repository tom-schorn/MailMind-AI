"""Claude AI integration for spam analysis."""

import json
import logging
from dataclasses import dataclass
from typing import Optional

import anthropic

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """Result from spam analysis step."""

    spam_score: float  # 0.0 = legitimate, 1.0 = definite spam
    reason: str
    is_certain: bool  # True if we can skip remaining steps


class ClaudeAnalyzer:
    """Claude-based email spam analyzer."""

    def __init__(self, api_key: str):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = "claude-3-5-haiku-20241022"

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
                return AnalysisResult(
                    spam_score=float(data.get("spam_score", 0.5)),
                    reason=str(data.get("reason", "Unknown")),
                    is_certain=bool(data.get("is_certain", False)),
                )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse response: {e}")

        return AnalysisResult(
            spam_score=0.5,
            reason="Could not parse analysis result",
            is_certain=False,
        )

    def analyze_subject(self, subject: str) -> AnalysisResult:
        """Analyze email subject for spam indicators."""
        system_prompt = """You are a conservative email spam analyzer. Analyze ONLY the email subject line.

CRITICAL - These are NOT spam (score 0.0-0.3):
- Newsletters from ANY company (waipu, Apple, Patreon, Freeletics, etc.)
- Marketing emails from legitimate brands
- Notification emails (receipts, shipping, account updates)
- Social media notifications
- App notifications (Kleinanzeigen, Temu, etc.)
- Publisher emails (Rheinwerk, etc.)
- Subscription services

ONLY flag as spam (score 0.9+) if subject contains:
- Obvious lottery/inheritance scams
- Clear phishing ("Your account will be deleted")
- Crypto/investment scams
- Adult content spam
- Random gibberish text

When in doubt, score LOW (0.0-0.3). False positives are worse than missed spam.

Respond with JSON only:
{"spam_score": 0.0-1.0, "reason": "brief explanation", "is_certain": true/false}

is_certain=true ONLY if it's obvious malicious spam (score >= 0.95)"""

        return self._analyze(system_prompt, f"Subject: {subject}")

    def analyze_sender(self, sender: str) -> AnalysisResult:
        """Analyze sender address for spam indicators."""
        system_prompt = """You are a conservative email spam analyzer. Analyze ONLY the sender address.

CRITICAL - These senders are LEGITIMATE (score 0.0-0.2):
- Any @apple.com, @google.com, @microsoft.com, @amazon.com
- Newsletter services (@mail.*, @news.*, @info.*, @newsletter.*)
- Known brands (patreon, freeletics, waipu, temu, kleinanzeigen, adguard, etc.)
- Publisher/media companies (rheinwerk, etc.)
- Any recognizable company domain

ONLY flag as spam (score 0.9+) if sender has:
- Obvious typosquatting (paypa1.com, amaz0n.com, g00gle.com)
- Random character strings in domain
- .xyz, .top, .click domains with suspicious names
- Clear impersonation attempts

When in doubt, score LOW (0.0-0.3). Legitimate businesses use many different email domains.

Respond with JSON only:
{"spam_score": 0.0-1.0, "reason": "brief explanation", "is_certain": true/false}

is_certain=true ONLY if sender is obviously malicious (score >= 0.95)"""

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

        system_prompt = """You are an email security analyzer. Analyze the authentication headers.

Check for:
- SPF: pass/fail/none
- DKIM: valid/invalid/missing
- DMARC: pass/fail
- Suspicious authentication results

IMPORTANT: Missing DKIM alone is not definitive spam. Many legitimate small senders don't use DKIM.

Respond with JSON only:
{"spam_score": 0.0-1.0, "reason": "brief explanation", "is_certain": true/false}

is_certain=true only if headers show clear forgery (score >= 0.9)"""

        return self._analyze(system_prompt, header_text)

    def analyze_content(self, body: str, subject: str) -> AnalysisResult:
        """Analyze email content for spam patterns."""
        # Limit body to avoid token overuse - privacy focused
        truncated_body = body[:1000] if len(body) > 1000 else body

        system_prompt = """You are a conservative email spam analyzer. Analyze the email content.

CRITICAL - These are LEGITIMATE (score 0.0-0.3):
- Newsletters with unsubscribe links
- Marketing emails from brands
- Product announcements
- Account notifications
- Receipts and confirmations
- Social media digests
- App notifications
- Promotional offers from real companies

ONLY flag as spam (score 0.9+) if content contains:
- Phishing: fake login pages, credential harvesting
- Scams: lottery wins, inheritance, crypto schemes
- Malware: suspicious attachments, download links
- Adult content spam
- Advance fee fraud

Normal marketing language is NOT spam. Urgency in legitimate notifications is NOT spam.
When in doubt, score LOW (0.0-0.3).

Respond with JSON only:
{"spam_score": 0.0-1.0, "reason": "brief explanation", "is_certain": true/false}"""

        content = f"Subject: {subject}\n\nBody:\n{truncated_body}"
        return self._analyze(system_prompt, content)
