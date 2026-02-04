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
