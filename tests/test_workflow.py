"""Tests for workflow logic."""

import pytest

from mailmind.ai.claude import SpamCategory
from mailmind.workflow.steps import StepResult


class TestSpamCategory:
    """Test spam category enum."""

    def test_all_categories_exist(self):
        assert SpamCategory.LEGITIMATE.value == "legitimate"
        assert SpamCategory.PHISHING.value == "phishing"
        assert SpamCategory.SCAM.value == "scam"
        assert SpamCategory.MALWARE.value == "malware"
        assert SpamCategory.ADULT.value == "adult"
        assert SpamCategory.UNKNOWN.value == "unknown"

    def test_category_from_string(self):
        assert SpamCategory("phishing") == SpamCategory.PHISHING
        assert SpamCategory("scam") == SpamCategory.SCAM

    def test_invalid_category_raises(self):
        with pytest.raises(ValueError):
            SpamCategory("invalid")


class TestStepResult:
    """Test step result dataclass."""

    def test_create_step_result(self):
        result = StepResult(
            step_name="subject",
            spam_score=0.85,
            reason="Suspicious subject",
            is_certain=True,
            should_stop=True,
            category=SpamCategory.PHISHING,
        )

        assert result.step_name == "subject"
        assert result.spam_score == 0.85
        assert result.is_certain is True
        assert result.should_stop is True
        assert result.category == SpamCategory.PHISHING

    def test_default_category(self):
        result = StepResult(
            step_name="test",
            spam_score=0.5,
            reason="Test",
            is_certain=False,
            should_stop=False,
        )

        assert result.category == SpamCategory.UNKNOWN


class TestScoreCalculation:
    """Test weighted score calculation logic."""

    def test_single_step_score(self):
        """Single step should return its score normalized by weight."""
        results = [
            StepResult("subject", 0.8, "Test", False, False),
        ]

        # Weight for subject is 0.2
        # Weighted score = 0.8 * 0.2 = 0.16
        # Total weight = 0.2
        # Final = 0.16 / 0.2 = 0.8
        score = self._calculate_score(results)
        assert score == pytest.approx(0.8)

    def test_all_steps_equal_score(self):
        """All steps with same score should return that score."""
        results = [
            StepResult("subject", 0.5, "Test", False, False),
            StepResult("sender", 0.5, "Test", False, False),
            StepResult("headers", 0.5, "Test", False, False),
            StepResult("content", 0.5, "Test", False, False),
        ]

        score = self._calculate_score(results)
        assert score == 0.5

    def test_weighted_average(self):
        """Score should be weighted average."""
        results = [
            StepResult("subject", 1.0, "Test", False, False),   # weight 0.2
            StepResult("sender", 0.0, "Test", False, False),    # weight 0.25
            StepResult("headers", 0.0, "Test", False, False),   # weight 0.25
            StepResult("content", 0.0, "Test", False, False),   # weight 0.3
        ]

        # Expected: (1.0*0.2 + 0*0.25 + 0*0.25 + 0*0.3) / (0.2+0.25+0.25+0.3)
        # = 0.2 / 1.0 = 0.2
        score = self._calculate_score(results)
        assert score == 0.2

    def test_empty_results(self):
        """Empty results should return 0."""
        score = self._calculate_score([])
        assert score == 0.0

    def _calculate_score(self, results):
        """Calculate weighted score (copied from runner logic)."""
        if not results:
            return 0.0

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


class TestCategoryDetermination:
    """Test category determination from step results."""

    def test_legitimate_when_not_spam(self):
        results = [
            StepResult("subject", 0.1, "OK", False, False, SpamCategory.LEGITIMATE),
        ]

        category = self._determine_category(results, is_spam=False)
        assert category == SpamCategory.LEGITIMATE

    def test_most_common_category(self):
        results = [
            StepResult("subject", 0.9, "Phish", True, True, SpamCategory.PHISHING),
            StepResult("sender", 0.9, "Phish", True, True, SpamCategory.PHISHING),
            StepResult("content", 0.8, "Scam", True, False, SpamCategory.SCAM),
        ]

        category = self._determine_category(results, is_spam=True)
        assert category == SpamCategory.PHISHING

    def test_unknown_when_no_spam_categories(self):
        results = [
            StepResult("subject", 0.9, "Unknown", True, True, SpamCategory.UNKNOWN),
            StepResult("sender", 0.9, "Legit", True, True, SpamCategory.LEGITIMATE),
        ]

        category = self._determine_category(results, is_spam=True)
        assert category == SpamCategory.UNKNOWN

    def _determine_category(self, results, is_spam):
        """Determine category (copied from runner logic)."""
        from collections import Counter

        if not is_spam:
            return SpamCategory.LEGITIMATE

        spam_categories = [
            r.category
            for r in results
            if r.category not in (SpamCategory.LEGITIMATE, SpamCategory.UNKNOWN)
        ]

        if not spam_categories:
            return SpamCategory.UNKNOWN

        counter = Counter(spam_categories)
        return counter.most_common(1)[0][0]
