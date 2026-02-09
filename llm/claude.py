"""Claude (Anthropic) LLM analyzer implementation."""

import json
import logging
from typing import Dict

import anthropic

from llm.base import LLMAnalyzer, AnalysisResult


MODEL_MAP = {
    "haiku": "claude-haiku-4-5-20251001",
    "sonnet": "claude-sonnet-4-5-20250929",
}

CATEGORY_LIST = "legitimate, newsletter, commercial, spam, scam, phishing, malware, adult, unknown"

SYSTEM_PROMPT = f"""You are an email spam classifier. Analyze the provided email data and classify it.

Categories: {CATEGORY_LIST}

Category definitions:
- legitimate: Normal, expected correspondence (personal, business, transactional)
- newsletter: Opted-in newsletters, digests, subscriptions the user signed up for
- commercial: Marketing emails, promotions, ads, sales offers (not explicitly subscribed)
- spam: Unsolicited bulk email, generic junk mail
- scam: Fraudulent emails trying to trick users (fake invoices, lottery, inheritance)
- phishing: Emails attempting to steal credentials or personal information
- malware: Emails containing or linking to malicious software
- adult: Adult/explicit content
- unknown: Cannot determine

Respond ONLY with valid JSON:
{{"score": 0.0, "category": "legitimate", "is_certain": false, "reasoning": "brief explanation"}}

- score: 0.0 (definitely legitimate) to 1.0 (definitely spam/malicious)
- is_certain: true if you are very confident (>90%) in the classification
- Keep reasoning under 100 characters"""


class ClaudeAnalyzer(LLMAnalyzer):
    """Analyzes email components using Claude API."""

    def __init__(self, api_key: str, model: str = "haiku", sensitivity: int = 5, logger: logging.Logger = None):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = MODEL_MAP.get(model, model)  # Allow custom model names too
        self.sensitivity = sensitivity
        self.logger = logger or logging.getLogger("MailMind.LLM.Claude")

    def _query(self, prompt: str) -> AnalysisResult:
        """Send a classification query to Claude."""
        try:
            # LOGGING: DEBUG-Level für API-Request
            self.logger.debug(f"Sending request to Claude API (model: {self.model})")
            self.logger.debug(f"Prompt length: {len(prompt)} chars")

            sensitivity_note = ""
            if self.sensitivity <= 3:
                sensitivity_note = "\nBe lenient - only flag obvious spam/threats. Newsletters and commercial emails are acceptable."
            elif self.sensitivity >= 8:
                sensitivity_note = "\nBe strict - flag anything unsolicited. Commercial emails and unknown senders should score higher."

            response = self.client.messages.create(
                model=self.model,
                max_tokens=200,
                system=SYSTEM_PROMPT + sensitivity_note,
                messages=[{"role": "user", "content": prompt}],
            )

            text = response.content[0].text.strip()

            # Strip markdown code fences if present (bugfix v1.11)
            if text.startswith("```"):
                lines = text.split("\n")
                lines = [l for l in lines if not l.strip().startswith("```")]
                text = "\n".join(lines).strip()

            data = json.loads(text)

            score = max(0.0, min(1.0, float(data.get("score", 0.5))))
            category_str = data.get("category", "unknown").lower()

            # LOGGING: INFO-Level für Ergebnis
            self.logger.info(
                f"Claude response: score={score:.2f}, category={category_str}, certain={data.get('is_certain', False)}"
            )

            return AnalysisResult(
                score=score,
                category=category_str,
                is_certain=bool(data.get("is_certain", False)),
                reasoning=str(data.get("reasoning", ""))[:200],
                raw_data={"provider": "claude", "model": self.model, "response": data}
            )

        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse Claude response: {e} | Raw: {text[:200]}")
            return AnalysisResult(
                score=0.5,
                category="unknown",
                is_certain=False,
                reasoning="Parse error",
                raw_data={"error": str(e)}
            )
        except anthropic.APIError as e:
            self.logger.error(f"Claude API error: {e}")
            return AnalysisResult(
                score=0.5,
                category="error",
                is_certain=False,
                reasoning=f"API error: {e}",
                raw_data={"error": str(e)}
            )

    def analyze_headers(self, headers: Dict) -> AnalysisResult:
        """Analyze email headers for spam indicators."""
        self.logger.debug("Analyzing email headers")
        relevant = {}
        for key in ["From", "Reply-To", "Return-Path", "X-Mailer", "X-Spam-Status",
                     "X-Spam-Score", "Authentication-Results", "DKIM-Signature",
                     "Received-SPF", "X-Priority", "List-Unsubscribe"]:
            if key in headers:
                val = headers[key]
                if isinstance(val, (list, tuple)):
                    val = str(val[0]) if val else ""
                relevant[key] = str(val)[:200]

        if not relevant:
            self.logger.debug("No relevant headers found")
            return AnalysisResult(
                score=0.3,
                category="unknown",
                is_certain=False,
                reasoning="No relevant headers"
            )

        prompt = f"Analyze these email headers for spam indicators:\n{json.dumps(relevant, indent=2)}"
        return self._query(prompt)

    def analyze_sender(self, sender: str) -> AnalysisResult:
        """Analyze sender address for spam indicators."""
        self.logger.debug(f"Analyzing sender: {sender}")
        if not sender:
            return AnalysisResult(
                score=0.5,
                category="unknown",
                is_certain=False,
                reasoning="No sender"
            )

        prompt = f"Analyze this email sender address for spam/phishing indicators:\n{sender}"
        return self._query(prompt)

    def analyze_subject(self, subject: str) -> AnalysisResult:
        """Analyze email subject for spam indicators."""
        self.logger.debug(f"Analyzing subject: {subject[:50]}...")
        if not subject:
            return AnalysisResult(
                score=0.3,
                category="unknown",
                is_certain=False,
                reasoning="No subject"
            )

        prompt = f"Analyze this email subject line for spam indicators:\n{subject}"
        return self._query(prompt)

    def analyze_content(self, body: str, subject: str = "") -> AnalysisResult:
        """Analyze email body content for spam indicators."""
        self.logger.debug(f"Analyzing content (body length: {len(body)} chars)")
        if not body:
            return AnalysisResult(
                score=0.3,
                category="unknown",
                is_certain=False,
                reasoning="No body content"
            )

        # Truncate body to avoid excessive token usage
        truncated = body[:3000]
        context = f"Subject: {subject}\n\n" if subject else ""
        prompt = f"Analyze this email content for spam/phishing/scam indicators:\n{context}{truncated}"
        return self._query(prompt)
