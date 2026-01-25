"""Spam handling: mark and move spam emails."""

import logging
from typing import List, Set

from ..ai.claude import SpamCategory
from ..imap.client import Email, IMAPClient
from .steps import StepResult

logger = logging.getLogger(__name__)

# Category folder mapping
CATEGORY_FOLDERS = {
    SpamCategory.PHISHING: "Phishing",
    SpamCategory.SCAM: "Scam",
    SpamCategory.MALWARE: "Malware",
    SpamCategory.ADULT: "Adult",
}


class SpamHandler:
    """Handle spam emails: move to category subfolders."""

    def __init__(self, imap_client: IMAPClient, spam_folder: str):
        self.imap = imap_client
        self.spam_folder = spam_folder
        self._created_folders: Set[str] = set()

    def handle_spam(
        self, email: Email, results: List[StepResult], final_score: float
    ) -> None:
        """Mark email as spam and move to spam folder."""
        logger.info(f"Handling spam email {email.uid}")

        # Create new subject
        new_subject = self._mark_subject(email.subject)

        # Create new body with explanation
        new_body = self._inject_explanation(
            email.body_html or email.body_text,
            results,
            final_score,
            is_html=bool(email.body_html),
        )

        try:
            # Modify email in place and then move to spam
            self.imap.modify_and_move_to_spam(
                email, new_subject, new_body, self.spam_folder
            )
            logger.info(f"Spam email {email.uid} processed and moved to {self.spam_folder}")
        except Exception as e:
            logger.error(f"Failed to process spam email {email.uid}: {e}")
            # Fallback: just move without modification
            try:
                self.imap.move_to_folder(email.uid, self.spam_folder)
                logger.info(f"Fallback: moved email {email.uid} to spam without modification")
            except Exception as e2:
                logger.error(f"Fallback move also failed: {e2}")

    def _mark_subject(self, subject: str) -> str:
        """Add *SPAM* prefix to subject."""
        if subject.startswith("*SPAM*"):
            return subject
        return f"*SPAM* {subject}"

    def _inject_explanation(
        self,
        body: str,
        results: List[StepResult],
        final_score: float,
        is_html: bool,
    ) -> str:
        """Inject spam explanation box into email body."""
        explanation = self._build_explanation(results, final_score, is_html)

        if is_html:
            # Inject after <body> tag or at beginning
            body_lower = body.lower()
            body_pos = body_lower.find("<body")
            if body_pos >= 0:
                # Find end of body tag
                end_pos = body.find(">", body_pos) + 1
                return body[:end_pos] + explanation + body[end_pos:]
            else:
                return explanation + body
        else:
            return explanation + "\n\n" + body

    def _build_explanation(
        self, results: List[StepResult], final_score: float, is_html: bool
    ) -> str:
        """Build the spam explanation box."""
        reasons = [f"- {r.step_name}: {r.reason} (score: {r.spam_score:.2f})"
                   for r in results if r.spam_score > 0.3]

        if is_html:
            reasons_html = "<br>".join(
                f"<li><b>{r.step_name}</b>: {r.reason} "
                f"(score: {r.spam_score:.2f})</li>"
                for r in results if r.spam_score > 0.3
            )

            return f"""
<div style="background-color: #ffebee; border: 2px solid #f44336; border-radius: 8px; padding: 16px; margin: 16px 0; font-family: Arial, sans-serif;">
    <h3 style="color: #c62828; margin: 0 0 12px 0;">⚠️ This email was flagged as spam</h3>
    <p style="margin: 0 0 8px 0;"><b>Spam Score:</b> {final_score:.0%}</p>
    <p style="margin: 0 0 8px 0;"><b>Analysis Results:</b></p>
    <ul style="margin: 0; padding-left: 20px;">
        {reasons_html}
    </ul>
    <p style="font-size: 12px; color: #666; margin: 12px 0 0 0;">Analyzed by MailMind-AI</p>
</div>
"""
        else:
            reasons_text = "\n".join(reasons)
            return f"""
========================================
⚠️ THIS EMAIL WAS FLAGGED AS SPAM
========================================
Spam Score: {final_score:.0%}

Analysis Results:
{reasons_text}

Analyzed by MailMind-AI
========================================
"""

    def move_to_spam(
        self, email: Email, category: SpamCategory = SpamCategory.UNKNOWN
    ) -> None:
        """Move email to spam category subfolder."""
        # Determine target folder
        if category in CATEGORY_FOLDERS:
            subfolder = CATEGORY_FOLDERS[category]
            target_folder = f"{self.spam_folder}/{subfolder}"
        else:
            target_folder = self.spam_folder

        # Ensure folder exists
        self._ensure_folder_exists(target_folder)

        try:
            self.imap.move_to_folder(email.uid, target_folder)
            logger.info(f"Moved email {email.uid} to {target_folder}")
        except Exception as e:
            logger.error(f"Failed to move email {email.uid} to {target_folder}: {e}")
            # Fallback to main spam folder
            if target_folder != self.spam_folder:
                try:
                    self.imap.move_to_folder(email.uid, self.spam_folder)
                    logger.info(f"Fallback: moved to {self.spam_folder}")
                except Exception as e2:
                    logger.error(f"Fallback also failed: {e2}")

    def _ensure_folder_exists(self, folder: str) -> None:
        """Create folder if it doesn't exist (cached)."""
        if folder in self._created_folders:
            return

        try:
            self.imap.create_folder(folder)
            self._created_folders.add(folder)
        except Exception:
            # Folder might already exist
            self._created_folders.add(folder)
