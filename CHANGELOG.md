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

### Planned
- OAuth2 authentication support
- Email templates
- Scheduled rule execution
- Email forwarding
- Advanced filtering options
- Dashboard with statistics
- Email preview in rules
