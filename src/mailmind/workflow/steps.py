"""Individual workflow steps for spam analysis."""

import logging
from dataclasses import dataclass
from typing import Optional

from ..ai.claude import AnalysisResult, ClaudeAnalyzer
from ..imap.client import Email

logger = logging.getLogger(__name__)


@dataclass
class StepResult:
    """Result from a workflow step."""

    step_name: str
    spam_score: float
    reason: str
    is_certain: bool
    should_stop: bool  # True if we should stop the workflow


class WorkflowSteps:
    """Collection of spam analysis workflow steps."""

    def __init__(self, analyzer: ClaudeAnalyzer, spam_threshold: float = 0.7):
        self.analyzer = analyzer
        self.spam_threshold = spam_threshold

    def _to_step_result(
        self, step_name: str, result: AnalysisResult
    ) -> StepResult:
        """Convert AnalysisResult to StepResult."""
        should_stop = result.is_certain and result.spam_score >= self.spam_threshold
        return StepResult(
            step_name=step_name,
            spam_score=result.spam_score,
            reason=result.reason,
            is_certain=result.is_certain,
            should_stop=should_stop,
        )

    def analyze_subject(self, email: Email) -> StepResult:
        """Step 1: Analyze email subject."""
        logger.info(f"Step 1: Analyzing subject for email {email.uid}")
        result = self.analyzer.analyze_subject(email.subject)
        step_result = self._to_step_result("subject", result)
        logger.info(
            f"Subject analysis: score={step_result.spam_score:.2f}, "
            f"certain={step_result.is_certain}, stop={step_result.should_stop}"
        )
        return step_result

    def analyze_sender(self, email: Email) -> StepResult:
        """Step 2: Analyze sender address."""
        logger.info(f"Step 2: Analyzing sender for email {email.uid}")
        result = self.analyzer.analyze_sender(email.sender)
        step_result = self._to_step_result("sender", result)
        logger.info(
            f"Sender analysis: score={step_result.spam_score:.2f}, "
            f"certain={step_result.is_certain}, stop={step_result.should_stop}"
        )
        return step_result

    def analyze_headers(self, email: Email) -> StepResult:
        """Step 3: Analyze email headers."""
        logger.info(f"Step 3: Analyzing headers for email {email.uid}")
        result = self.analyzer.analyze_headers(email.headers)
        step_result = self._to_step_result("headers", result)
        logger.info(
            f"Header analysis: score={step_result.spam_score:.2f}, "
            f"certain={step_result.is_certain}, stop={step_result.should_stop}"
        )
        return step_result

    def analyze_content(self, email: Email) -> StepResult:
        """Step 4: Analyze email content."""
        logger.info(f"Step 4: Analyzing content for email {email.uid}")
        body = email.body_text or email.body_html
        result = self.analyzer.analyze_content(body, email.subject)
        step_result = self._to_step_result("content", result)
        logger.info(
            f"Content analysis: score={step_result.spam_score:.2f}, "
            f"certain={step_result.is_certain}, stop={step_result.should_stop}"
        )
        return step_result
