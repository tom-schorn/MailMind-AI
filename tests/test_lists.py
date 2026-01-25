"""Tests for whitelist/blacklist domain management."""

import json
import tempfile
from pathlib import Path

import pytest

from mailmind.lists import DomainLists


class TestDomainExtraction:
    """Test domain extraction from various sender formats."""

    def test_simple_email(self):
        assert DomainLists.extract_domain("user@example.com") == "example.com"

    def test_email_with_name(self):
        assert DomainLists.extract_domain("John Doe <john@example.com>") == "example.com"

    def test_email_with_quotes(self):
        assert DomainLists.extract_domain('"John Doe" <john@example.com>') == "example.com"

    def test_subdomain(self):
        assert DomainLists.extract_domain("news@mail.example.com") == "mail.example.com"

    def test_uppercase(self):
        assert DomainLists.extract_domain("USER@EXAMPLE.COM") == "example.com"

    def test_whitespace(self):
        assert DomainLists.extract_domain("  user@example.com  ") == "example.com"


class TestDomainLists:
    """Test whitelist/blacklist operations."""

    @pytest.fixture
    def temp_file(self):
        """Create a temporary file for testing."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{}")
            return f.name

    @pytest.fixture
    def lists(self, temp_file):
        """Create DomainLists instance with temp file."""
        return DomainLists(temp_file)

    def test_whitelist_domain(self, lists):
        lists.whitelist("user@example.com")
        assert lists.is_whitelisted("other@example.com")
        assert not lists.is_blacklisted("other@example.com")

    def test_blacklist_domain(self, lists):
        lists.blacklist("spam@malicious.com")
        assert lists.is_blacklisted("other@malicious.com")
        assert not lists.is_whitelisted("other@malicious.com")

    def test_whitelist_removes_from_blacklist(self, lists):
        lists.blacklist("user@example.com")
        assert lists.is_blacklisted("user@example.com")

        lists.whitelist("user@example.com")
        assert lists.is_whitelisted("user@example.com")
        assert not lists.is_blacklisted("user@example.com")

    def test_blacklist_removes_from_whitelist(self, lists):
        lists.whitelist("user@example.com")
        assert lists.is_whitelisted("user@example.com")

        lists.blacklist("user@example.com")
        assert lists.is_blacklisted("user@example.com")
        assert not lists.is_whitelisted("user@example.com")

    def test_persistence(self, temp_file):
        # Create and add entries
        lists1 = DomainLists(temp_file)
        lists1.whitelist("good@example.com")
        lists1.blacklist("bad@spam.com")

        # Load in new instance
        lists2 = DomainLists(temp_file)
        assert lists2.is_whitelisted("user@example.com")
        assert lists2.is_blacklisted("user@spam.com")

    def test_get_lists(self, lists):
        lists.whitelist("a@white.com")
        lists.whitelist("b@white.com")
        lists.blacklist("c@black.com")

        whitelist = lists.get_whitelist()
        blacklist = lists.get_blacklist()

        assert "white.com" in whitelist
        assert "black.com" in blacklist
        assert len(whitelist) == 1  # Both emails have same domain
        assert len(blacklist) == 1
