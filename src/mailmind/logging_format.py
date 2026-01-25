"""Structured logging format for better console readability."""

import sys

# Box drawing characters
LINE_HEAVY = "\u2501"  # ━
LINE_LIGHT = "\u2500"  # ─
CORNER_TL = "\u250c"   # ┌
CORNER_TR = "\u2510"   # ┐
CORNER_BL = "\u2514"   # └
CORNER_BR = "\u2518"   # ┘
VERT = "\u2502"        # │

# Status icons
ICON_OK = "\u2713"     # ✓
ICON_FAIL = "\u2717"   # ✗
ICON_ARROW = ">>"

# Width for boxes
WIDTH = 75


class ConsoleOutput:
    """Structured console output for email analysis."""

    def __init__(self):
        # Use UTF-8 stdout for Windows compatibility
        if sys.platform == "win32":
            sys.stdout.reconfigure(encoding='utf-8')

    def email_header(self, uid: str, subject: str, sender: str) -> None:
        """Print email analysis header."""
        line = LINE_HEAVY * WIDTH
        subject_truncated = subject[:60] + "..." if len(subject) > 60 else subject

        print(f"\n{line}")
        print(f" ANALYZING EMAIL #{uid}")
        print(f" Subject: {subject_truncated}")
        print(f" From: {sender}")
        print(line)

    def step_result(
        self,
        step_num: int,
        total: int,
        name: str,
        score: float,
        reason: str,
        is_spam: bool,
    ) -> None:
        """Print a single step result."""
        icon = ICON_FAIL if is_spam else ICON_OK
        reason_truncated = reason[:40] + "..." if len(reason) > 40 else reason

        print(f"  [{step_num}/{total}] {name:<10} {icon} Score: {score:.2f}  {reason_truncated}")

    def early_exit(self, reason: str) -> None:
        """Print early exit notice."""
        print(f"  {ICON_ARROW} Early exit: {reason}")

    def result_box(self, is_spam: bool, score: float, spam_folder: str = None) -> None:
        """Print final result box."""
        inner_width = WIDTH - 2

        if is_spam:
            status = f"{ICON_FAIL} SPAM"
            if spam_folder:
                status += f" (moved to {spam_folder})"
        else:
            status = f"{ICON_OK} LEGITIMATE"

        score_text = f"Final Score: {score:.2f}"
        padding = inner_width - len(status) - len(score_text) - 2

        print()
        print(f"{CORNER_TL}{LINE_LIGHT * inner_width}{CORNER_TR}")
        print(f"{VERT} {status}{' ' * padding}{score_text} {VERT}")
        print(f"{CORNER_BL}{LINE_LIGHT * inner_width}{CORNER_BR}")
        print()

    def info(self, message: str) -> None:
        """Print info message."""
        print(f" {ICON_OK} {message}")

    def error(self, message: str) -> None:
        """Print error message."""
        print(f" {ICON_FAIL} {message}")

    def status(self, message: str) -> None:
        """Print status message without icon."""
        print(f" {message}")


# Global instance
console = ConsoleOutput()
