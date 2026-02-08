import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import anthropic


class SpamCategory(Enum):
    LEGITIMATE = "legitimate"
    NEWSLETTER = "newsletter"
    COMMERCIAL = "commercial"
    SPAM = "spam"
    SCAM = "scam"
    PHISHING = "phishing"
    MALWARE = "malware"
    ADULT = "adult"
    UNKNOWN = "unknown"


@dataclass
class AnalysisResult:
    """Result of a single analysis step."""
    score: float
    category: SpamCategory
    is_certain: bool
    reasoning: str


@dataclass
class SpamResult:
    """Final result of spam analysis pipeline."""
    is_spam: bool
    score: float
    category: SpamCategory
    step_results: list = field(default_factory=list)
    stopped_early: bool = False
    reason: str = ""


MODEL_MAP = {
    "haiku": "claude-haiku-4-5-20251001",
    "sonnet": "claude-sonnet-4-5-20250929",
}

CATEGORY_LIST = ", ".join([c.value for c in SpamCategory])

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


class ClaudeAnalyzer:
    """Analyzes email components using Claude API."""

    def __init__(self, api_key: str, model: str = "haiku", sensitivity: int = 5, logger: logging.Logger = None):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = MODEL_MAP.get(model, MODEL_MAP["haiku"])
        self.sensitivity = sensitivity
        self.logger = logger or logging.getLogger("MailMind.SpamService")

    def _query(self, prompt: str) -> AnalysisResult:
        """Send a classification query to Claude."""
        try:
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
            data = json.loads(text)

            score = max(0.0, min(1.0, float(data.get("score", 0.5))))
            category_str = data.get("category", "unknown").lower()

            try:
                category = SpamCategory(category_str)
            except ValueError:
                category = SpamCategory.UNKNOWN

            return AnalysisResult(
                score=score,
                category=category,
                is_certain=bool(data.get("is_certain", False)),
                reasoning=str(data.get("reasoning", ""))[:200],
            )

        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse Claude response: {e}")
            return AnalysisResult(score=0.5, category=SpamCategory.UNKNOWN, is_certain=False, reasoning="Parse error")
        except anthropic.APIError as e:
            self.logger.error(f"Claude API error: {e}")
            return AnalysisResult(score=0.5, category=SpamCategory.UNKNOWN, is_certain=False, reasoning=f"API error: {e}")

    def analyze_headers(self, headers: dict) -> AnalysisResult:
        """Analyze email headers for spam indicators."""
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
            return AnalysisResult(score=0.3, category=SpamCategory.UNKNOWN, is_certain=False, reasoning="No relevant headers")

        prompt = f"Analyze these email headers for spam indicators:\n{json.dumps(relevant, indent=2)}"
        return self._query(prompt)

    def analyze_sender(self, sender: str) -> AnalysisResult:
        """Analyze sender address for spam indicators."""
        if not sender:
            return AnalysisResult(score=0.5, category=SpamCategory.UNKNOWN, is_certain=False, reasoning="No sender")

        prompt = f"Analyze this email sender address for spam/phishing indicators:\n{sender}"
        return self._query(prompt)

    def analyze_subject(self, subject: str) -> AnalysisResult:
        """Analyze email subject for spam indicators."""
        if not subject:
            return AnalysisResult(score=0.3, category=SpamCategory.UNKNOWN, is_certain=False, reasoning="No subject")

        prompt = f"Analyze this email subject line for spam indicators:\n{subject}"
        return self._query(prompt)

    def analyze_content(self, body: str, subject: str = "") -> AnalysisResult:
        """Analyze email body content for spam indicators."""
        if not body:
            return AnalysisResult(score=0.3, category=SpamCategory.UNKNOWN, is_certain=False, reasoning="No body content")

        # Truncate body to avoid excessive token usage
        truncated = body[:3000]
        context = f"Subject: {subject}\n\n" if subject else ""
        prompt = f"Analyze this email content for spam/phishing/scam indicators:\n{context}{truncated}"
        return self._query(prompt)


class SpamAnalyzer:
    """Orchestrates the 4-step spam analysis pipeline."""

    STEP_WEIGHTS = {
        "headers": 0.25,
        "sender": 0.25,
        "subject": 0.20,
        "content": 0.30,
    }

    def __init__(self, api_key: str, model: str = "haiku", sensitivity: int = 5, logger: logging.Logger = None):
        self.claude = ClaudeAnalyzer(api_key, model, sensitivity, logger)
        self.sensitivity = sensitivity
        self.logger = logger or logging.getLogger("MailMind.SpamService")

    def analyze_email(self, email, whitelist_domains: list = None, blacklist_domains: list = None) -> SpamResult:
        """
        Run 4-step spam analysis pipeline on an email.

        Args:
            email: EmailMessage dataclass
            whitelist_domains: List of trusted domain strings
            blacklist_domains: List of blocked domain strings

        Returns:
            SpamResult with final classification
        """
        sender_domain = self._extract_domain(email.sender)

        # Whitelist check
        if whitelist_domains and sender_domain in whitelist_domains:
            self.logger.debug(f"Sender {email.sender} is whitelisted")
            return SpamResult(
                is_spam=False,
                score=0.0,
                category=SpamCategory.LEGITIMATE,
                stopped_early=True,
                reason=f"Whitelisted domain: {sender_domain}",
            )

        # Blacklist check
        if blacklist_domains and sender_domain in blacklist_domains:
            self.logger.debug(f"Sender {email.sender} is blacklisted")
            return SpamResult(
                is_spam=True,
                score=1.0,
                category=SpamCategory.SPAM,
                stopped_early=True,
                reason=f"Blacklisted domain: {sender_domain}",
            )

        step_results = []
        steps = [
            ("headers", lambda: self.claude.analyze_headers(email.headers)),
            ("sender", lambda: self.claude.analyze_sender(email.sender)),
            ("subject", lambda: self.claude.analyze_subject(email.subject)),
            ("content", lambda: self.claude.analyze_content(email.body_text or email.body_html, email.subject)),
        ]

        stopped_early = False

        for step_name, step_fn in steps:
            result = step_fn()
            step_results.append({
                "step": step_name,
                "score": result.score,
                "category": result.category.value,
                "is_certain": result.is_certain,
                "reasoning": result.reasoning,
            })

            self.logger.debug(f"Step '{step_name}': score={result.score:.2f}, category={result.category.value}, certain={result.is_certain}")

            # Early exit if certain
            if result.is_certain:
                self.logger.info(f"Early exit at step '{step_name}': {result.category.value} (score={result.score:.2f})")
                stopped_early = True
                break

        # Calculate weighted score
        total_weight = 0.0
        weighted_score = 0.0
        for step_data in step_results:
            weight = self.STEP_WEIGHTS.get(step_data["step"], 0.25)
            weighted_score += step_data["score"] * weight
            total_weight += weight

        if total_weight > 0:
            final_score = weighted_score / total_weight
        else:
            final_score = 0.5

        # Determine category by majority vote
        final_category = self._determine_category(step_results)

        # Apply sensitivity threshold
        threshold = 1.0 - (self.sensitivity / 10.0)  # sensitivity 5 -> threshold 0.5
        is_spam = final_score >= threshold and final_category not in (SpamCategory.LEGITIMATE, SpamCategory.NEWSLETTER)

        reason_parts = [f"{s['step']}:{s['category']}({s['score']:.1f})" for s in step_results]

        return SpamResult(
            is_spam=is_spam,
            score=round(final_score, 3),
            category=final_category,
            step_results=step_results,
            stopped_early=stopped_early,
            reason=f"Score={final_score:.2f}, Category={final_category.value} [{', '.join(reason_parts)}]",
        )

    @staticmethod
    def _extract_domain(sender: str) -> Optional[str]:
        """Extract domain from email address."""
        if not sender:
            return None
        if "@" in sender:
            # Handle "Name <email@domain>" format
            if "<" in sender and ">" in sender:
                sender = sender[sender.index("<") + 1:sender.index(">")]
            parts = sender.split("@")
            if len(parts) == 2:
                return parts[1].lower().strip()
        return None

    @staticmethod
    def _determine_category(step_results: list) -> SpamCategory:
        """Determine final category from step results by majority vote."""
        if not step_results:
            return SpamCategory.UNKNOWN

        # Count category occurrences, weighted by step importance
        category_scores = {}
        weights = {"headers": 0.25, "sender": 0.25, "subject": 0.20, "content": 0.30}

        for step_data in step_results:
            cat = step_data["category"]
            weight = weights.get(step_data["step"], 0.25)
            category_scores[cat] = category_scores.get(cat, 0.0) + weight

        # Return highest weighted category
        best_category = max(category_scores, key=category_scores.get)
        try:
            return SpamCategory(best_category)
        except ValueError:
            return SpamCategory.UNKNOWN
