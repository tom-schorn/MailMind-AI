"""Whitelist and blacklist management for sender domains."""

import json
import logging
from pathlib import Path
from typing import Set

logger = logging.getLogger(__name__)

DEFAULT_FILE = "mailmind_lists.json"

# Default whitelist for common legitimate domains
DEFAULT_WHITELIST = {
    # Tech companies
    "apple.com",
    "icloud.com",
    "google.com",
    "microsoft.com",
    "amazon.com",
    "amazon.de",
    # Dating services
    "parship.com",
    "parship.de",
    "mail.parship.com",
    "lovescout24.de",
    "elitepartner.de",
    "lemonswan.de",
    # Shopping & Payment
    "ebay.de",
    "ebay.com",
    "paypal.com",
    "paypal.de",
    "klarna.com",
    "klarna.de",
    # Streaming
    "netflix.com",
    "spotify.com",
    # Social & Services
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "xing.com",
}


class DomainLists:
    """Manage whitelisted and blacklisted sender domains."""

    def __init__(self, file_path: str = DEFAULT_FILE):
        self.file_path = Path(file_path)
        self._whitelist: Set[str] = set()
        self._blacklist: Set[str] = set()
        self._load()

        # Pre-populate whitelist with defaults if empty
        if not self._whitelist:
            self._whitelist = DEFAULT_WHITELIST.copy()
            self._save()
            logger.info(f"Pre-populated whitelist with {len(self._whitelist)} default domains")

    def _load(self) -> None:
        """Load lists from file."""
        if not self.file_path.exists():
            return

        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self._whitelist = set(data.get("whitelist", []))
                self._blacklist = set(data.get("blacklist", []))
                logger.info(
                    f"Loaded {len(self._whitelist)} whitelisted, "
                    f"{len(self._blacklist)} blacklisted domains"
                )
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load lists: {e}")

    def _save(self) -> None:
        """Save lists to file."""
        try:
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "whitelist": sorted(self._whitelist),
                        "blacklist": sorted(self._blacklist),
                    },
                    f,
                    indent=2,
                )
        except IOError as e:
            logger.error(f"Failed to save lists: {e}")

    @staticmethod
    def extract_domain(sender: str) -> str:
        """Extract domain from sender address."""
        # Handle "Name <email@domain.com>" format
        if "<" in sender and ">" in sender:
            start = sender.find("<") + 1
            end = sender.find(">")
            sender = sender[start:end]

        # Extract domain from email
        if "@" in sender:
            return sender.split("@")[-1].lower().strip()

        return sender.lower().strip()

    def whitelist(self, sender: str) -> None:
        """Add sender domain to whitelist (removes from blacklist)."""
        domain = self.extract_domain(sender)
        if not domain:
            return

        self._whitelist.add(domain)
        self._blacklist.discard(domain)
        self._save()
        logger.info(f"Whitelisted domain: {domain}")

    def blacklist(self, sender: str) -> None:
        """Add sender domain to blacklist (removes from whitelist)."""
        domain = self.extract_domain(sender)
        if not domain:
            return

        self._blacklist.add(domain)
        self._whitelist.discard(domain)
        self._save()
        logger.info(f"Blacklisted domain: {domain}")

    def is_whitelisted(self, sender: str) -> bool:
        """Check if sender domain is whitelisted."""
        domain = self.extract_domain(sender)
        return domain in self._whitelist

    def is_blacklisted(self, sender: str) -> bool:
        """Check if sender domain is blacklisted."""
        domain = self.extract_domain(sender)
        return domain in self._blacklist

    def get_whitelist(self) -> Set[str]:
        """Get copy of whitelist."""
        return self._whitelist.copy()

    def get_blacklist(self) -> Set[str]:
        """Get copy of blacklist."""
        return self._blacklist.copy()
