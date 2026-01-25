# MailMind-AI

Docker-based E-Mail Agent that monitors IMAP inbox and analyzes incoming emails for spam using Claude API.

## Features

- IMAP connection with IDLE support (polling fallback)
- Step-by-step spam analysis workflow with early exit
- Spam marking: subject prefix `*SPAM*`, explanation box in body
- All configuration via environment variables

## Quick Start

```bash
docker build -t mailmind-ai:0.1.0 .
docker run --env-file .env mailmind-ai:0.1.0
```

## Configuration

Copy `.env.example` to `.env` and configure:

| Variable | Description | Required |
|----------|-------------|----------|
| `IMAP_HOST` | IMAP server hostname | Yes |
| `IMAP_PORT` | IMAP port (default: 993) | No |
| `IMAP_USER` | IMAP username | Yes |
| `IMAP_PASSWORD` | IMAP password | Yes |
| `IMAP_FOLDER` | Folder to monitor (default: INBOX) | No |
| `IMAP_SPAM_FOLDER` | Spam destination folder | Yes |
| `IMAP_USE_IDLE` | Use IDLE if supported (default: true) | No |
| `IMAP_POLL_INTERVAL` | Polling interval in seconds (default: 60) | No |
| `ANTHROPIC_API_KEY` | Claude API key | Yes |
| `SPAM_THRESHOLD` | Score threshold for spam (default: 0.7) | No |
| `LOG_LEVEL` | Logging level (default: INFO) | No |

## License

MIT
