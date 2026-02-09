"""LLM abstraction layer for multi-provider support."""

from llm.base import LLMAnalyzer, AnalysisResult
from llm.claude import ClaudeAnalyzer
from llm.gemini import GeminiAnalyzer
from llm.openai import OpenAIAnalyzer
from llm.ollama import OllamaAnalyzer


def create_analyzer(llm_config, sensitivity: int, logger) -> LLMAnalyzer:
    """
    Factory function to create appropriate LLM analyzer based on config.

    Args:
        llm_config: LLMConfig instance from database
        sensitivity: Spam detection sensitivity (1-10)
        logger: Logger instance

    Returns:
        LLMAnalyzer instance

    Raises:
        ValueError: If provider is not supported
    """
    if llm_config.provider == 'claude':
        return ClaudeAnalyzer(llm_config.api_key, llm_config.model, sensitivity, logger)
    elif llm_config.provider == 'gemini':
        return GeminiAnalyzer(llm_config.api_key, llm_config.model, sensitivity, logger)
    elif llm_config.provider == 'openai':
        return OpenAIAnalyzer(llm_config.api_key, llm_config.model, sensitivity, logger)
    elif llm_config.provider == 'ollama':
        return OllamaAnalyzer(llm_config.endpoint, llm_config.model, sensitivity, logger)
    else:
        raise ValueError(f"Unsupported LLM provider: {llm_config.provider}")


__all__ = [
    'LLMAnalyzer',
    'AnalysisResult',
    'ClaudeAnalyzer',
    'GeminiAnalyzer',
    'OpenAIAnalyzer',
    'OllamaAnalyzer',
    'create_analyzer'
]
