"""Workflow runner for spam analysis."""

import logging
from dataclasses import dataclass
from typing import List, Optional

from ..ai.claude import ClaudeAnalyzer
from ..imap.client import Email, IMAPClient
from .spam_handler import SpamHandler
from .steps import StepResult, WorkflowSteps

logger = logging.getLogger(__name__)


@dataclass
class WorkflowResult:
    """Final result of spam analysis workflow."""

    email_uid: str
    is_spam: bool
    final_score: float
    step_results: List[StepResult]
    stopped_early: bool
    stopping_step: Optional[str]


class WorkflowRunner:
    """Orchestrate the spam analysis workflow."""

    def __init__(
        self,
        imap_client: IMAPClient,
        analyzer: ClaudeAnalyzer,
        spam_folder: str,
        spam_threshold: float = 0.7,
    ):
        self.steps = WorkflowSteps(analyzer, spam_threshold)
        self.spam_handler = SpamHandler(imap_client, spam_folder)
        self.spam_threshold = spam_threshold

    def process_email(self, email: Email) -> WorkflowResult:
        """Run the full spam analysis workflow on an email."""
        logger.info(f"Processing email {email.uid}: {email.subject[:50]}...")

        results: List[StepResult] = []
        stopped_early = False
        stopping_step: Optional[str] = None

        # Step 1: Analyze subject
        result = self.steps.analyze_subject(email)
        results.append(result)
        if result.should_stop:
            stopped_early = True
            stopping_step = result.step_name
            logger.info(f"Early exit at step 1 (subject): {result.reason}")
        else:
            # Step 2: Analyze sender
            result = self.steps.analyze_sender(email)
            results.append(result)
            if result.should_stop:
                stopped_early = True
                stopping_step = result.step_name
                logger.info(f"Early exit at step 2 (sender): {result.reason}")
            else:
                # Step 3: Analyze headers
                result = self.steps.analyze_headers(email)
                results.append(result)
                if result.should_stop:
                    stopped_early = True
                    stopping_step = result.step_name
                    logger.info(f"Early exit at step 3 (headers): {result.reason}")
                else:
                    # Step 4: Analyze content
                    result = self.steps.analyze_content(email)
                    results.append(result)

        # Calculate final score
        final_score = self._calculate_final_score(results)
        is_spam = final_score >= self.spam_threshold

        logger.info(
            f"Email {email.uid} analysis complete: "
            f"spam={is_spam}, score={final_score:.2f}, "
            f"early_stop={stopped_early}"
        )

        # Handle spam - just move without modification
        if is_spam:
            self.spam_handler.move_to_spam(email)

        return WorkflowResult(
            email_uid=email.uid,
            is_spam=is_spam,
            final_score=final_score,
            step_results=results,
            stopped_early=stopped_early,
            stopping_step=stopping_step,
        )

    def _calculate_final_score(self, results: List[StepResult]) -> float:
        """Calculate weighted final spam score."""
        if not results:
            return 0.0

        # Weights for each step
        weights = {
            "subject": 0.2,
            "sender": 0.25,
            "headers": 0.25,
            "content": 0.3,
        }

        total_weight = 0.0
        weighted_score = 0.0

        for result in results:
            weight = weights.get(result.step_name, 0.25)
            weighted_score += result.spam_score * weight
            total_weight += weight

        if total_weight == 0:
            return 0.0

        return weighted_score / total_weight
