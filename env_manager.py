import os
from dotenv import load_dotenv, set_key, find_dotenv

def load_env_settings():
    """Load current .env settings."""
    load_dotenv()
    return {
        'FLASK_SECRET_KEY': os.getenv('FLASK_SECRET_KEY', ''),
        'FLASK_DEBUG': os.getenv('FLASK_DEBUG', 'False'),
        'FLASK_HOST': os.getenv('FLASK_HOST', '0.0.0.0'),
        'FLASK_PORT': os.getenv('FLASK_PORT', '5000'),
        'DATABASE_URL': os.getenv('DATABASE_URL', 'sqlite:///storage.db'),
        'DATABASE_DEBUG': os.getenv('DATABASE_DEBUG', 'False')
    }

def save_env_settings(data):
    """Save settings to .env file."""
    env_file = find_dotenv()
    if not env_file:
        env_file = '.env'
        # Create .env file if it doesn't exist
        if not os.path.exists(env_file):
            with open(env_file, 'w') as f:
                f.write('# Flask Configuration\n')

    for key, value in data.items():
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
