# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
