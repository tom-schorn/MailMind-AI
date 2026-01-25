# MailMind-AI

Docker-based E-Mail Agent that monitors IMAP inbox and analyzes incoming emails for spam using Claude API.

## Features

- IMAP connection with IDLE support (polling fallback)
- Step-by-step spam analysis workflow with early exit
- Spam category detection: phishing, scam, malware, adult
- Automatic sorting into category subfolders
- Whitelist/blacklist learning from user actions
- Configurable sensitivity and AI model
- Structured console output with status icons
- All configuration via environment variables

## Quick Start

```bash
# Using Docker Compose
docker-compose up -d

# Or build and run manually
docker build -t mailmind-ai:latest .
docker run --env-file .env -v mailmind-data:/app/data mailmind-ai:latest
```

## Configuration

Copy `.env.example` to `.env` and configure:

### IMAP Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `IMAP_HOST` | IMAP server hostname | Required |
| `IMAP_PORT` | IMAP port | 993 |
| `IMAP_USER` | IMAP username | Required |
| `IMAP_PASSWORD` | IMAP password | Required |
| `IMAP_FOLDER` | Folder to monitor | INBOX |
| `IMAP_SPAM_FOLDER` | Spam destination folder | Required |
| `IMAP_USE_IDLE` | Use IDLE if supported | true |
| `IMAP_POLL_INTERVAL` | Polling interval (seconds) | 60 |

### Spam Detection

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | Claude API key | Required |
| `CLAUDE_MODEL` | AI model (haiku/sonnet/opus) | haiku |
| `SPAM_SENSITIVITY` | Detection sensitivity (1-10) | 5 |
| `SPAM_PROMPT` | Custom prompt or "Standard" | Standard |
| `ANALYSIS_LIMIT` | Max emails on startup (0=unlimited) | 50 |

### Other

| Variable | Description | Default |
|----------|-------------|---------|
| `LOG_LEVEL` | Logging level | INFO |

## Spam Categories

Detected spam is sorted into subfolders:

- `Spam/Phishing` - Credential harvesting, fake login pages
- `Spam/Scam` - Lottery, inheritance, crypto schemes
- `Spam/Malware` - Suspicious attachments, download links
- `Spam/Adult` - Explicit content, dating spam

## Learning System

MailMind-AI learns from your actions:

- **Move email FROM spam folder** → Sender domain is whitelisted
- **Move email TO spam folder** → Sender domain is blacklisted

Whitelisted senders skip AI analysis. Blacklisted senders are marked as spam immediately.

## License

MIT
