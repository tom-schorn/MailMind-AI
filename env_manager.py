import os
from dotenv import load_dotenv, set_key
from path_manager import get_env_file, get_database_url, ensure_data_dir

def load_env_settings():
    """Load current .env settings."""
    ensure_data_dir()
    env_file = get_env_file()
    load_dotenv(env_file)
    return {
        'FLASK_SECRET_KEY': os.getenv('FLASK_SECRET_KEY', ''),
        'FLASK_DEBUG': os.getenv('FLASK_DEBUG', 'False'),
        'FLASK_HOST': os.getenv('FLASK_HOST', '0.0.0.0'),
        'FLASK_PORT': os.getenv('FLASK_PORT', '5000'),
        'DATABASE_URL': os.getenv('DATABASE_URL', get_database_url()),
        'DATABASE_DEBUG': os.getenv('DATABASE_DEBUG', 'False')
    }

def save_env_settings(data):
    """Save settings to .env file."""
    ensure_data_dir()
    env_file = get_env_file()

    # Create .env file if it doesn't exist
    if not os.path.exists(env_file):
        with open(env_file, 'w') as f:
            f.write('# Flask Configuration\n')

    for key, value in data.items():
        set_key(env_file, key, str(value))

def sync_env_from_system():
    """Sync system environment variables into .env file.

    This allows Docker environment variables to override .env settings.
    Only updates keys that are explicitly set in system environment.
    """
    ensure_data_dir()
    env_file = get_env_file()

    # Create .env if it doesn't exist
    if not os.path.exists(env_file):
        with open(env_file, 'w') as f:
            f.write('# Flask Configuration\n')

    # Keys that can be overridden from system env
    env_keys = [
        'FLASK_SECRET_KEY',
        'FLASK_DEBUG',
        'FLASK_HOST',
        'FLASK_PORT',
        'DATABASE_URL',
        'DATABASE_DEBUG'
    ]

    # Only write to .env if the env var is explicitly set in system
    for key in env_keys:
        value = os.environ.get(key)
        if value is not None:  # Only if explicitly set
            set_key(env_file, key, str(value))

def validate_env_value(key, value):
    """Validate environment variable values."""
    if key == 'FLASK_PORT':
        try:
            port = int(value)
            if port < 1 or port > 65535:
                return False, 'Port must be between 1 and 65535'
        except ValueError:
            return False, 'Port must be a number'

    if key == 'FLASK_SECRET_KEY':
        if len(value) < 32:
            return False, 'Secret key should be at least 32 characters long'

    if key in ['FLASK_DEBUG', 'DATABASE_DEBUG']:
        if value.lower() not in ['true', 'false', '1', '0', 'yes', 'no']:
            return False, 'Must be True/False, 1/0, or yes/no'

    return True, None
