import json
import os
from path_manager import get_config_file, ensure_data_dir

CONFIG_FILE = None  # Will be set dynamically

def get_default_config():
    """Return default configuration settings."""
    from path_manager import DATA_DIR
    log_path = os.path.join(DATA_DIR, 'logs', 'mailmind.log')

    return {
        'email_check_interval': 5,
        'log_level': 'INFO',
        'log_to_file': True,
        'log_file_path': log_path,
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
    ensure_data_dir()
    config_file = get_config_file()

    if not os.path.exists(config_file):
        return get_default_config()

    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return get_default_config()

def save_config(data):
    """Save configuration to config.json file."""
    ensure_data_dir()
    config_file = get_config_file()

    with open(config_file, 'w') as f:
        json.dump(data, f, indent=2)
