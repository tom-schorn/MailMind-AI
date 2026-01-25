"""Individual workflow steps for spam analysis."""

from dataclasses import dataclass

from ..ai.claude import AnalysisResult, ClaudeAnalyzer, SpamCategory
from ..imap.client import Email


@dataclass
class StepResult:
    """Result from a workflow step."""

    step_name: str
    spam_score: float
    reason: str
    is_certain: bool
    should_stop: bool  # True if we should stop the workflow
    category: SpamCategory = SpamCategory.UNKNOWN


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
            category=result.category,
        )

    def analyze_subject(self, email: Email) -> StepResult:
        """Step 1: Analyze email subject."""
        result = self.analyzer.analyze_subject(email.subject)
        return self._to_step_result("subject", result)

    def analyze_sender(self, email: Email) -> StepResult:
        """Step 2: Analyze sender address."""
        result = self.analyzer.analyze_sender(email.sender)
        return self._to_step_result("sender", result)

    def analyze_headers(self, email: Email) -> StepResult:
        """Step 3: Analyze email headers."""
        result = self.analyzer.analyze_headers(email.headers)
        return self._to_step_result("headers", result)

    def analyze_content(self, email: Email) -> StepResult:
        """Step 4: Analyze email content."""
        body = email.body_text or email.body_html
        result = self.analyzer.analyze_content(body, email.subject)
        return self._to_step_result("content", result)
