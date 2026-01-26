# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.3.0] - 2026-01-26

### Changed
- Logging-System: Tagesweise Logs im `logs/` Unterordner
- Log-Dateien werden automatisch nach 3 Tagen gelöscht
- Log-Rotation erfolgt um Mitternacht statt größenbasiert
- Konfigurierbar via LOG_DIR und LOG_RETENTION_DAYS

## [0.4.2.0] - 2026-01-26

### Added
- Default whitelist with common legitimate domains (Apple, Parship, PayPal, Netflix, etc.)
- Whitelist auto-populates on first run with 25+ trusted domains
- Extended known brands in spam detection: Parship, Lovescout24, Elitepartner, eBay, Klarna, Spotify

### Changed
- Improved SPAM_SENSITIVITY documentation in .env.example with detailed explanations for each level
- Sender analysis now recognizes more dating services and shopping platforms

### Fixed
- Reduced false positives for legitimate services like Parship and Apple
- Better recognition of newsletter subdomains and known brands

## [0.4.1.0] - 2026-01-26

### Fixed
- Fixed UID invalidation during spam categorization by refetching UIDs after each move
- Fixed emails remaining in spam folder: only mark as analyzed when successfully categorized
- LEGITIMATE emails in spam folder are no longer marked as analyzed and will be reanalyzed

### Added
- Spam/Unknown subfolder for emails that cannot be clearly categorized
- Version-based state reset mechanism for mailmind_state.json
- State version tracking to automatically reset analyzed UIDs on upgrades

### Changed
- UNKNOWN-categorized emails are now moved to Spam/Unknown instead of staying in main folder
- State file now includes version field for upgrade detection

## [0.4.0.0] - 2026-01-26

### Added
- Separate workflows for pre-release and release deployments
- Pre-release workflow deploys with tags `x.x.x.x-pre` and `pre-latest`
- Release workflow deploys with tags `x.x.x.x` and `latest`
- Automatic spam categorization on startup
- Pre-latest Docker tag for versions < 1.0.0

### Changed
- Versioning scheme changed to 4-digit format (MAJOR.MINOR.PATCH.BUILD)
- BUILD number increments with every commit
- BUILD resets to 0 when MAJOR/MINOR/PATCH changes
- Fixed ConsoleOutput AttributeError in spam_monitor.py

## [0.3.0] - 2026-01-25

### Added
- implement automatic versioning system

### Changed
- improve Docker registry tagging strategy
- prepare v0.2.0 release


## [0.2.0] - 2026-01-25

### Added
- Configurable spam sensitivity (1-10 scale via SPAM_SENSITIVITY)
- Model selection: haiku, sonnet, opus (via CLAUDE_MODEL)
- Custom prompt override (via SPAM_PROMPT)
- Spam category detection: phishing, scam, malware, adult
- Automatic category subfolders in spam folder
- Improved spam prompts with red flag detection
- Whitelist/blacklist system for sender domains
- Spam folder monitoring: learns from user actions
- Emails moved from spam by user are whitelisted
- Emails moved to spam by user are blacklisted

### Changed
- Prompts now include sensitivity-based instructions
- Spam emails sorted into category subfolders (Spam/Phishing, Spam/Scam, etc.)
- Whitelisted senders skip AI analysis entirely
- Blacklisted senders are marked as spam immediately

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
