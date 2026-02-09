"""Spam analysis pipeline using LLM providers."""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from llm import create_analyzer, LLMAnalyzer


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
    ERROR = "error"  # Added for errors during analysis


@dataclass
class SpamResult:
    """Final result of spam analysis pipeline."""
    is_spam: bool
    score: float
    category: SpamCategory
    step_results: list = field(default_factory=list)
    stopped_early: bool = False
    reason: str = ""


class SpamAnalyzer:
    """Orchestrates the spam analysis pipeline using configurable LLM provider."""

    STEP_WEIGHTS = {
        "headers": 0.20,
        "sender": 0.15,
        "subject": 0.15,
        "content": 0.25,
        "domain": 0.25,  # Domain spoofing check (highest weight!)
    }

    def __init__(self, llm_config, sensitivity: int = 5, logger: logging.Logger = None):
        """
        Initialize spam analyzer with LLM config.

        Args:
            llm_config: LLMConfig instance from database
            sensitivity: Spam detection sensitivity (1-10)
            logger: Logger instance
        """
        self.llm_analyzer = create_analyzer(llm_config, sensitivity, logger)
        self.sensitivity = sensitivity
        self.logger = logger or logging.getLogger("MailMind.SpamAnalyzer")

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
        # LOGGING: DEBUG-Level für Start
        self.logger.debug(f"Starting spam analysis for email UID {email.uid}")
        self.logger.debug(
            f"Whitelist: {len(whitelist_domains or [])} domains, Blacklist: {len(blacklist_domains or [])} domains"
        )

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
            ("headers", lambda: self.llm_analyzer.analyze_headers(email.headers)),
            ("sender", lambda: self.llm_analyzer.analyze_sender(email.sender)),
            ("subject", lambda: self.llm_analyzer.analyze_subject(email.subject)),
            ("content", lambda: self.llm_analyzer.analyze_content(email.body_text or email.body_html, email.subject)),
        ]

        # Add domain spoofing check if analyzer supports it (Claude only for now)
        if hasattr(self.llm_analyzer, 'analyze_domain_spoofing'):
            sender_name = self._extract_sender_name(email.sender)
            body_preview = (email.body_text or email.body_html or "")[:500]
            steps.append((
                "domain",
                lambda: self.llm_analyzer.analyze_domain_spoofing(
                    email.sender, sender_name, email.subject, body_preview
                )
            ))
            self.logger.debug("Domain spoofing check enabled")

        stopped_early = False

        for step_name, step_fn in steps:
            result = step_fn()

            # Convert category string to SpamCategory enum
            try:
                category = SpamCategory(result.category)
            except ValueError:
                category = SpamCategory.UNKNOWN

            step_results.append({
                "step": step_name,
                "score": result.score,
                "category": category.value,
                "is_certain": result.is_certain,
                "reasoning": result.reasoning,
            })

            self.logger.debug(
                f"Step '{step_name}': score={result.score:.2f}, category={category.value}, certain={result.is_certain}"
            )

            # Early exit if certain
            if result.is_certain:
                self.logger.info(
                    f"Early exit at step '{step_name}': {category.value} (score={result.score:.2f})"
                )
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

        # LOGGING: INFO-Level für Ergebnis
        self.logger.info(
            f"Spam analysis complete: score={final_score:.2f}, category={final_category.value}, is_spam={is_spam}"
        )

        return SpamResult(
            is_spam=is_spam,
            score=round(final_score, 3),
            category=final_category,
            step_results=step_results,
            stopped_early=stopped_early,
            reason=f"Score={final_score:.2f}, Category={final_category.value} [{', '.join(reason_parts)}]",
        )

    @staticmethod
    def _extract_sender_name(sender: str) -> str:
        """
        Extract display name from email address.

        Examples:
            "John Doe <john@example.com>" -> "John Doe"
            "john@example.com" -> "john@example.com"
            "Lotto24 GmbH <winner@spam.com>" -> "Lotto24 GmbH"
        """
        if not sender:
            return ""

        # Check for display name format: "Name <email>"
        if '<' in sender and '>' in sender:
            name_part = sender.split('<')[0].strip()
            # Remove quotes if present
            name_part = name_part.strip('"').strip("'")
            return name_part if name_part else sender

        return sender

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
