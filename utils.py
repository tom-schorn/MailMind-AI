"""Centralized path management for data files."""
import os

# Base data directory - can be overridden via DATA_DIR env var
DATA_DIR = os.getenv('DATA_DIR', '.')

def get_data_path(filename: str) -> str:
    """Get full path for a data file in the data directory.

    Args:
        filename: Name of the file (e.g., '.env', 'storage.db', 'config.json')

    Returns:
        Full path to the file in the data directory
    """
    return os.path.join(DATA_DIR, filename)

def ensure_data_dir():
    """Ensure data directory exists."""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR, exist_ok=True)

def get_env_file() -> str:
    """Get path to .env file."""
    return get_data_path('.env')

def get_config_file() -> str:
    """Get path to config.json file."""
    return get_data_path('config.json')

def get_database_url() -> str:
    """Get database URL from environment or default to data directory."""
    default_db_path = get_data_path('storage.db')
    return os.getenv('DATABASE_URL', f'sqlite:///{default_db_path}')


# Environment Management
from dotenv import load_dotenv, set_key

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
