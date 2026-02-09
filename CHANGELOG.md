# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.4-pre] - 2026-02-09

### Added
- **Domain Spoofing Detection**: New anti-phishing feature in spam analysis pipeline (Claude only)
  - Validates sender email domain against expected domain extracted from display name
  - Highest weight (25%) in spam scoring to prioritize domain authenticity
  - Detects impersonation attempts (e.g., "Lotto24 GmbH" from @gmail.com → Phishing)
  - Significantly reduces false positives for legitimate companies (Pearl, ING, McDonald's, Lotto24)
  - Uses LLM to determine expected domains contextually

### Fixed
- **IDLE Watch Performance**: Eliminated redundant UID fetching on watch startup
  - Pass initial UIDs from folder watcher to watch() method
  - Avoids re-fetching thousands of emails from Sent/Sent Messages folders
  - Startup time reduced from minutes to seconds for accounts with many emails
- **Dry-Run Performance**: Limited email fetch to 100 most recent emails (was unlimited)

## [2.1.3-pre] - 2026-02-09

### Fixed
- **IDLE Watch Debugging**: Added comprehensive DEBUG logging to diagnose IDLE watch issues
  - Logs before/after UID fetch to identify hanging points
  - Logs before watch() and _watch_idle() calls
  - Limited initial email scan to 100 most recent emails for performance
  - Detailed logging of watch mode (IDLE vs POLLING) and parameters

## [2.0.0] - 2026-02-09

### Breaking Changes
- **Multi-LLM Support**: Replaced hardcoded Claude API with configurable LLM providers (Claude, Gemini, OpenAI, Ollama)
- **AccountHandler Architecture**: Each email account now runs with dedicated handler instance for better isolation
- **Rule Hash Tracking**: Email processing now tracks rule configuration changes via SHA256 hash instead of simple UID list
- **Removed Auto-Spam Rules**: Auto-generated `[Auto-Spam]` rules have been removed. Users must create their own rules using `spam_score` and `spam_category` conditions
- **Database Migration**: Automatic migration from v1.5.0 to v2.0.0 on startup (adds new tables, columns, indexes)

### Added
- **LLM Abstraction Layer**: `llm/` module with support for 4 providers:
  - Claude (Anthropic) - Recommended for best accuracy
  - Gemini (Google) - Alternative with good performance
  - OpenAI (ChatGPT) - Popular general-purpose AI
  - Ollama (Self-hosted) - Privacy-focused, no API key needed
- **Per-Account LLM Configuration**: Configure different LLM providers per account via `/accounts/<id>/llm`
- **AccountHandler Class**: New dedicated handler per account with:
  - In-memory processed UID cache (O(1) lookup)
  - Automatic rule hash calculation
  - LLM configuration loading
  - Reload signal polling
  - Persistent vs session-only tracking modes
- **Handler Configuration UI**: Configure tracking behavior via `/accounts/<id>/handler`
- **Negation Operators**: Added 6 new rule operators:
  - `contains_not` - Does NOT contain
  - `equals_not` - Is NOT equal to
  - `starts_with_not` - Does NOT start with
  - `ends_with_not` - Does NOT end with
  - `greater_than_not` - NOT greater than (≤)
  - `less_than_not` - NOT less than (≥)
- **Database Schema Changes**:
  - New table `llmconfig` - Per-account LLM provider configuration
  - New table `accounthandlerconfig` - Per-account handler settings
  - New column `emailruleapplication.rule_config_hash` - Tracks rule configuration changes
  - New index `idx_emailruleapplication_hash` - Optimizes processed email lookups

### Changed
- **Email Processing Flow**: Regular rules evaluated first, spam analysis only if no match (v1.11 bugfix preserved)
- **Spam Analysis**: Now uses account-specific LLM provider instead of global ANTHROPIC_API_KEY
- **Performance**: Processed email checks now use in-memory cache (O(1)) instead of DB query (O(log n))
- **Rule Changes**: Any rule modification triggers reprocessing with new rule hash (invalidates cache)
- **Dependencies**: Added `google-generativeai==0.8.3`, `openai==1.59.9`, `requests==2.32.3`

### Removed
- **Auto-Spam Rule Generation**: `_create_spam_auto_rules()` and `_delete_spam_auto_rules()` functions removed
- **Quick Action Panel**: Removed from account dashboard (UI simplification)
- **Global ANTHROPIC_API_KEY**: No longer used, replaced by per-account LLM configs

### Fixed
- All v1.11 bugfixes preserved (spam processing order, error persistence, subfolder handling, etc.)

### Migration Notes
- Database automatically migrates from v1.5.0 to v2.0.0 on startup
- All existing `[Auto-Spam]` rules are deleted during migration
- Users must configure LLM provider per account before spam detection works
- Existing `emailruleapplication` records are updated with current rule hash
- No manual intervention required for migration

### Security
- LLM API keys stored in database (plaintext) - Use Ollama for full privacy
- Future versions may add encryption for API keys

## [1.0.0-pre] - 2026-02-04

### Added

#### Core Backend
- Email service with multi-threaded architecture
- IMAP client with SSL/TLS/unencrypted support
- Auto-detection for IMAP encryption settings
- Rule engine with 12 condition operators
- Action execution engine with priority ordering
- Service status tracking and heartbeat monitoring
- Processed email tracking to prevent duplicates

#### Database Entities
- ServiceStatus for service health monitoring
- DryRunRequest for test request management
- DryRunResult for test result storage
- ProcessedEmail for duplicate prevention

#### Rule System
- Condition evaluation with AND/OR logic
- Support for fields: from, subject, body, to, header
- Operators: contains, equals, not_equals, starts_with, ends_with, greater_than, less_than, greater_equal, less_equal, date_older_than
- Actions: move_to_folder, copy_to_folder, add_label, mark_as_read, delete, modify_subject
- Rule priority and execution order management

#### Testing & Debugging
- Live dry-run testing in rule forms (without saving)
- Dry-run results page with detailed condition evaluation
- Live log popup with real-time progress tracking
- Progress indicator showing elapsed time
- Email count statistics (checked/matched/total)
- Limit to 10 matching emails per dry-run
- Maximum 100 emails scanned per test

#### Web Interface
- Email account management (add/edit/delete)
- Email rule management (add/edit/delete)
- Test button integrated in rule creation/editing
- Service status dashboard
- General settings page
- Real-time updates via AJAX polling

#### Configuration
- Service settings (heartbeat, polling intervals)
- IMAP settings (IDLE vs polling, reconnect delay)
- Logging configuration (level, file output)
- Auto-apply rules toggle

#### Logging
- Console and rotating file handler
- Configurable log levels
- Detailed IMAP operation logging
- Rule evaluation logging
- Test session tracking

### Fixed
- SSL/TLS connection handling with correct imap-tools classes
- Only matching emails displayed in dry-run results
- Proper email limit handling (10 matches vs 10 tested)

### Technical Details
- Python 3.12
- Flask web framework
- SQLAlchemy ORM
- imap-tools for IMAP operations
- Bootstrap 5 UI
- Multi-threaded service architecture
- Thread-safe session management

## [Unreleased]

## [2.2.0-pre] - 2026-02-09

### Added
- add domain spoofing detection and fix IDLE performance

### Changed
- bump version to 2.1.4-pre


## [2.1.3-pre] - 2026-02-09

### Changed
- bump version to 2.1.3-pre for hotfix deployment


## [2.1.2] - 2026-02-09

### Fixed
- add rule_config_hash column to EmailRuleApplication model


## [2.1.1] - 2026-02-09

### Fixed
- add LLM and handler configuration links to dashboard


## [2.1.0] - 2026-02-09

### Added
- v2.0.0 Multi-LLM Support & Architecture Refactoring (#17)

### Changed
- bump version to 1.11.0-pre, update changelog


## [1.11.0-pre] - 2026-02-09

### Added
- Whitelist/blacklist URL import from plaintext domain lists
- Error badge for failed analyses in spam log

### Fixed
- Strip markdown code fences from Claude API responses (JSON parse errors)
- Run spam analysis only when no regular rule matches (saves API costs)
- Auto-create missing IMAP spam subfolders on startup
- Learning monitor only watches main spam folder when auto_categorize is ON
- Persist Claude analysis errors in SpamAnalysis table for per-account visibility


## [1.10.0-pre] - 2026-02-08

### Added
- show active auto-rules and learning info in spam settings UI
- add spam folder learning monitor with auto-whitelist
- add auto-rules creation for spam detection settings


## [1.9.0-pre] - 2026-02-08

### Added
- add spam detection web UI and API endpoints
- integrate spam analysis into email processing pipeline
- add spam detection database models and migration
- add SpamService with Claude AI spam analysis pipeline

### Fixed
- make SpamConfig.changed_at nullable for initial insert


## [1.8.0-pre] - 2026-02-08

### Added
- add save_attachments action for email rules
- add attachment-based conditions for email rules

### Fixed
- resolve dry-run folder bug, group rules by folder, improve dashboard activity


## [1.7.0-pre] - 2026-02-08

### Added
- Restructure UI to account-centric navigation
- Attachment-based conditions: has_attachment, attachment_count, attachment_format, attachment_filename, attachment_size
- Size parsing with unit support (KB, MB, GB) for attachment_size condition
- Dynamic condition UI with MIME type selector, size input with unit, and radio buttons
- Save attachments action: automatically saves email attachments to DATA_DIR/attachments/<account>/<rule>/
- DB-based watcher reload signal: rule changes (add/edit/delete) trigger live watcher restart without service restart
- Database migration 1.3.0 -> 1.4.0 (email_subject in EmailRuleApplication, WatcherReloadSignal table)
- Email subject tracking in rule application history

### Fixed
- Dry-run and test-preview now use monitored_folder instead of defaulting to INBOX
- Rules list grouped by monitored folder with section headers and count badges
- Dashboard "Recent Activity" shows email subject, rule name, and human-readable actions instead of raw UIDs/IDs/JSON
- Docker health-check start-period increased from 5s to 30s to prevent false unhealthy state


## [1.6.0-pre] - 2026-02-08

### Added
- replace auto-reload with AJAX-based live log table
- add label management UI, API endpoints, and live log viewer
- add Label model and database migration to v1.3.0
- add date/label condition support and IMAP flag scanning
- add date filter and folder combobox to rule edit page
- add monitored folder visibility toggle and date filter conditions

### Fixed
- resolve code review issues in rule templates and models


## [1.5.3-pre] - 2026-02-08

### Changed
- revert config.json.example changes (configured via UI)
- pin dependency versions in requirements.txt
- add MIT license file

### Fixed
- implement IMAP IDLE hybrid architecture with proactive reconnect
- log warning when config file is corrupt instead of silently using defaults
- use stdlib urllib for Docker healthcheck instead of requests
- correct imap_test_connection import path
- replace bare except clauses with specific error handling


## [1.5.2-pre] - 2026-02-05

### Fixed
- update WebService imports after refactoring consolidation (#9)


## [1.5.1-pre] - 2026-02-05

### Fixed
- workflow_dispatch skips deploy job due to missing condition (#8)


## [1.5.0-pre] - 2026-02-05

### Added
- implement per-rule email tracking (#7)


## [1.4.0-pre] - 2026-02-05

### Added
- process all existing emails on startup (#6)


## [1.3.0-pre] - 2026-02-05

### Added
- add manual trigger for pre-release deployment workflow


## [1.2.3-pre] - 2026-02-05

### Fixed
- implement auto-reconnect for IMAP broken pipe errors


## [1.2.2-pre] - 2026-02-05

### Fixed
- use correct FolderInfo attribute 'delim' instead of 'delimiter'


## [1.2.1-pre] - 2026-02-05

### Fixed
- exclude pre-releases from release deployment workflow


## [1.2.0-pre] - 2026-02-05

### Added
- add configurable folder monitoring and dynamic folder selection


## [1.1.0-pre] - 2026-02-05

### Added
- Configurable monitored folder per email rule (previously hardcoded to INBOX)
- Dynamic folder selection in rule creation/edit UI via API endpoint
- Automatic folder creation for move/copy actions if folder doesn't exist
- Multi-folder watching: separate IMAP watcher thread per monitored folder
- Automatic database migration system with version tracking
- New `DatabaseVersion` entity for migration history
- API endpoint `/api/folders/<credential_id>` to fetch available IMAP folders
- IMAP client methods: `list_folders()`, `create_folder()`, `folder_exists()`
- Docker data volume and environment variable override

### Changed
- `EmailRule` entity now includes `monitored_folder` field (default: INBOX)
- Email service now spawns one watcher thread per unique monitored folder
- IMAP watch methods now accept `folder` parameter for dynamic folder monitoring
- Rule engine auto-creates target folders before move/copy actions (in production mode only)

### Migration
- Database automatically migrates from v1.0.0 to v1.1.0 on first service start
- Adds `monitored_folder` column to `emailrule` table with default value 'INBOX'
- Creates `databaseversion` table for future migration tracking
- Existing rules are preserved with default folder 'INBOX'

## [1.0.1-pre] - 2026-02-04

### Fixed
- handle pre-release version suffixes in bump script
- deploy pre-releases regardless of major version


### Planned
- OAuth2 authentication support
- Email templates
- Scheduled rule execution
- Email forwarding
- Advanced filtering options
- Dashboard with statistics
- Email preview in rules
