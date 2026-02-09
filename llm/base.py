"""Base classes for LLM analyzers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class AnalysisResult:
    """Result of a spam analysis step."""
    score: float  # 0.0 = legitimate, 1.0 = spam
    category: str  # SpamCategory value
    is_certain: bool  # Whether the analysis is confident
    reasoning: str  # Human-readable explanation
    raw_data: Dict[str, Any] = None  # Provider-specific raw response


class LLMAnalyzer(ABC):
    """
    Abstract base class for LLM-based spam analysis.

    All analyzers must implement a 4-step analysis pipeline:
    1. Headers analysis
    2. Sender analysis
    3. Subject analysis
    4. Content analysis

    Each step returns an AnalysisResult with a weighted score.
    """

    @abstractmethod
    def analyze_headers(self, headers: dict) -> AnalysisResult:
        """
        Analyze email headers for spam indicators.

        Args:
            headers: Dict of email headers (SPF, DKIM, Received, etc.)

        Returns:
            AnalysisResult with score and reasoning
        """
        pass

    @abstractmethod
    def analyze_sender(self, sender: str) -> AnalysisResult:
        """
        Analyze sender address for spam indicators.

        Args:
            sender: Email sender address

        Returns:
            AnalysisResult with score and reasoning
        """
        pass

    @abstractmethod
    def analyze_subject(self, subject: str) -> AnalysisResult:
        """
        Analyze subject line for spam indicators.

        Args:
            subject: Email subject line

        Returns:
            AnalysisResult with score and reasoning
        """
        pass

    @abstractmethod
    def analyze_content(self, body: str, subject: str = "") -> AnalysisResult:
        """
        Analyze email body content for spam indicators.

        Args:
            body: Email body text
            subject: Optional subject line for context

        Returns:
            AnalysisResult with score and reasoning
        """
        pass
