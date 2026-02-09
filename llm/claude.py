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

    def analyze_domain_spoofing(self, sender: str, sender_name: str, subject: str = "", body_preview: str = "") -> AnalysisResult:
        """
        Analyze if sender domain matches expected domain based on sender name.

        Detects domain spoofing where email claims to be from a known company
        but uses a different domain (e.g., "Lotto24" from @gmail.com).

        Args:
            sender: Actual email address (e.g., "winner@gmail.com")
            sender_name: Display name (e.g., "Lotto24 GmbH")
            subject: Email subject for additional context
            body_preview: First 500 chars of body for context

        Returns:
            AnalysisResult with high score if domain mismatch detected
        """
        self.logger.debug(f"Analyzing domain spoofing: '{sender_name}' <{sender}>")

        if not sender or not sender_name:
            return AnalysisResult(
                score=0.0,
                category="unknown",
                is_certain=False,
                reasoning="Insufficient data for domain check"
            )

        # Extract actual domain
        if '@' not in sender:
            return AnalysisResult(
                score=0.0,
                category="unknown",
                is_certain=False,
                reasoning="Invalid sender format"
            )

        actual_domain = sender.split('@')[1].lower()

        # Build context for LLM
        context = f"""
Sender name: {sender_name}
Actual email: {sender}
Subject: {subject[:100]}
Preview: {body_preview[:200]}

Based on the sender name "{sender_name}", what domain(s) would you expect this email to come from?
Consider official domains only (e.g., for "ING-DiBa" expect "ing.de", for "Lotto24" expect "lotto24.de").

Respond ONLY with valid JSON:
{{"expected_domains": ["domain1.com", "domain2.de"], "score": 0.0, "category": "legitimate", "is_certain": false, "reasoning": "brief explanation"}}

- expected_domains: List of legitimate domains for this sender (empty if personal/unknown sender)
- score: 0.0 if actual domain matches expected, 0.8-1.0 if clear mismatch (phishing), 0.5 if uncertain
- category: "phishing" if mismatch, "legitimate" if match, "unknown" if personal sender
""".strip()

        result = self._query(context)

        # Post-process: Check if actual domain matches expected
        try:
            expected_domains = result.raw_data.get("response", {}).get("expected_domains", [])
            if expected_domains:
                # Normalize domains
                expected_domains = [d.lower().strip() for d in expected_domains]

                # Check for match (exact or subdomain)
                is_match = any(
                    actual_domain == expected or actual_domain.endswith('.' + expected)
                    for expected in expected_domains
                )

                if not is_match:
                    # Domain mismatch detected - likely phishing!
                    self.logger.warning(
                        f"Domain spoofing detected: '{sender_name}' uses {actual_domain}, "
                        f"expected {expected_domains}"
                    )
                    return AnalysisResult(
                        score=0.9,  # High spam score for domain mismatch
                        category="phishing",
                        is_certain=True,
                        reasoning=f"Domain mismatch: expected {expected_domains[0]}, got {actual_domain}",
                        raw_data=result.raw_data
                    )
                else:
                    # Domain matches - legitimate
                    self.logger.debug(f"Domain match confirmed: {actual_domain} in {expected_domains}")
                    return AnalysisResult(
                        score=0.0,  # Legitimate
                        category="legitimate",
                        is_certain=True,
                        reasoning=f"Domain verified: {actual_domain}",
                        raw_data=result.raw_data
                    )
            else:
                # No expected domains (personal email, etc.) - return LLM result as-is
                return result

        except (KeyError, IndexError, AttributeError) as e:
            self.logger.warning(f"Failed to parse domain validation response: {e}")
            return result  # Return original LLM result
