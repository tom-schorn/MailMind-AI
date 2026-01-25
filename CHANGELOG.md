# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - TBD

### Added
- Configurable spam sensitivity (1-10 scale via SPAM_SENSITIVITY)
- Model selection: haiku, sonnet, opus (via CLAUDE_MODEL)
- Custom prompt override (via SPAM_PROMPT)
- Spam category detection: phishing, scam, malware, adult
- Automatic category subfolders in spam folder
- Improved spam prompts with red flag detection

### Changed
- Prompts now include sensitivity-based instructions
- Spam emails sorted into category subfolders (Spam/Phishing, Spam/Scam, etc.)

## [0.1.0] - TBD

### Added
- Initial release
- IMAP connection with IDLE support and polling fallback
- Step-by-step spam analysis workflow
- Claude API integration for spam detection
- Spam handling: move to spam folder
- State persistence to avoid reprocessing emails
- Configurable analysis limit (default: 50)
- SSL/STARTTLS auto-detection based on port

### Changed
- Conservative spam prompts to reduce false positives
- Spam emails are only moved, not modified (no subject/body changes)
- Structured console output with visual hierarchy and status icons
