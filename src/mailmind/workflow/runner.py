"""Workflow runner for spam analysis."""

import logging
from collections import Counter
from dataclasses import dataclass
from typing import List, Optional

from ..ai.claude import ClaudeAnalyzer, SpamCategory
from ..imap.client import Email, IMAPClient
from ..logging_format import console
from .spam_handler import SpamHandler
from .steps import StepResult, WorkflowSteps

logger = logging.getLogger(__name__)


@dataclass
class WorkflowResult:
    """Final result of spam analysis workflow."""

    email_uid: str
    is_spam: bool
    final_score: float
    category: SpamCategory
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
        console.email_header(email.uid, email.subject, email.sender)

        results: List[StepResult] = []
        stopped_early = False
        stopping_step: Optional[str] = None
        total_steps = 4

        # Step 1: Analyze subject
        result = self.steps.analyze_subject(email)
        results.append(result)
        self._print_step(1, total_steps, result)
        if result.should_stop:
            stopped_early = True
            stopping_step = result.step_name
            console.early_exit("Certain spam detected")
        else:
            # Step 2: Analyze sender
            result = self.steps.analyze_sender(email)
            results.append(result)
            self._print_step(2, total_steps, result)
            if result.should_stop:
                stopped_early = True
                stopping_step = result.step_name
                console.early_exit("Certain spam detected")
            else:
                # Step 3: Analyze headers
                result = self.steps.analyze_headers(email)
                results.append(result)
                self._print_step(3, total_steps, result)
                if result.should_stop:
                    stopped_early = True
                    stopping_step = result.step_name
                    console.early_exit("Certain spam detected")
                else:
                    # Step 4: Analyze content
                    result = self.steps.analyze_content(email)
                    results.append(result)
                    self._print_step(4, total_steps, result)

        # Calculate final score and category
        final_score = self._calculate_final_score(results)
        is_spam = final_score >= self.spam_threshold
        category = self._determine_category(results, is_spam)

        # Print result box
        console.result_box(
            is_spam,
            final_score,
            category.value if is_spam else None,
            self.spam_handler.spam_folder if is_spam else None,
        )

        # Handle spam - move to category subfolder
        if is_spam:
            self.spam_handler.move_to_spam(email, category)

        return WorkflowResult(
            email_uid=email.uid,
            is_spam=is_spam,
            final_score=final_score,
            category=category,
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

    def _determine_category(
        self, results: List[StepResult], is_spam: bool
    ) -> SpamCategory:
        """Determine the final spam category from step results."""
        if not is_spam:
            return SpamCategory.LEGITIMATE

        # Get all non-legitimate, non-unknown categories
        spam_categories = [
            r.category
            for r in results
            if r.category not in (SpamCategory.LEGITIMATE, SpamCategory.UNKNOWN)
        ]

        if not spam_categories:
            return SpamCategory.UNKNOWN

        # Return most common category
        counter = Counter(spam_categories)
        return counter.most_common(1)[0][0]

    def _print_step(self, step_num: int, total: int, result: StepResult) -> None:
        """Print step result to console."""
        is_spam = result.spam_score >= self.spam_threshold
        console.step_result(
            step_num,
            total,
            result.step_name.capitalize(),
            result.spam_score,
            result.reason,
            is_spam,
        )
