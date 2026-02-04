import json
import os

CONFIG_FILE = 'config.json'

def get_default_config():
    """Return default configuration settings."""
    return {
        'email_check_interval': 5,
        'log_level': 'INFO',
        'log_to_file': True,
        'log_file_path': 'logs/mailmind.log',
        'auto_apply_rules': False,
        'service': {
            'heartbeat_interval': 10,
            'dry_run_poll_interval': 5,
            'imap_reconnect_delay': 30,
            'use_imap_idle': True,
            'imap_poll_interval': 60
        }
    }

def load_config():
    """Load configuration from config.json file."""
    if not os.path.exists(CONFIG_FILE):
        return get_default_config()

    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return get_default_config()

def save_config(data):
    """Save configuration to config.json file."""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data, f, indent=2)
