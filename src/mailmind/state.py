"""State management for analyzed emails."""

import json
import logging
import os
from pathlib import Path
from typing import Set

logger = logging.getLogger(__name__)

DEFAULT_STATE_FILE = "mailmind_state.json"


class StateManager:
    """Persist analyzed email UIDs to avoid reprocessing."""

    def __init__(self, state_file: str = DEFAULT_STATE_FILE):
        self.state_file = Path(state_file)
        self._analyzed_uids: Set[str] = set()
        self._state_version = "0.4.1.0"
        self._load()

    def _load(self) -> None:
        """Load state from file."""
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                    # Check version and reset if outdated
                    file_version = data.get("version", "0.0.0.0")
                    if file_version < self._state_version:
                        logger.info(
                            f"State upgraded from {file_version} to {self._state_version}, resetting analyzed UIDs"
                        )
                        self._analyzed_uids = set()
                        self._save()  # Save new version immediately
                    else:
                        self._analyzed_uids = set(data.get("analyzed_uids", []))
                        logger.info(f"Loaded {len(self._analyzed_uids)} analyzed UIDs from state")
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load state file: {e}")
                self._analyzed_uids = set()

    def _save(self) -> None:
        """Save state to file."""
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "version": self._state_version,
                        "analyzed_uids": list(self._analyzed_uids),
                    },
                    f,
                    indent=2,
                )
        except IOError as e:
            logger.error(f"Failed to save state file: {e}")

    def is_analyzed(self, uid: str) -> bool:
        """Check if email UID was already analyzed."""
        return uid in self._analyzed_uids

    def mark_analyzed(self, uid: str) -> None:
        """Mark email UID as analyzed."""
        self._analyzed_uids.add(uid)
        self._save()

    def get_analyzed_uids(self) -> Set[str]:
        """Get all analyzed UIDs."""
        return self._analyzed_uids.copy()
