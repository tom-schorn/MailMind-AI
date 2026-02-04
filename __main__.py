import os
import threading
from dotenv import load_dotenv

from sqlalchemy import create_engine
from Entities import init_db
from Webservice import app
from EmailService import EmailService
from path_manager import get_env_file, get_database_url, ensure_data_dir
from env_manager import sync_env_from_system


def start_flask():
    """Start Flask web server in separate thread."""
    env_file = get_env_file()
    load_dotenv(env_file)

    flask_debug = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
    flask_host = os.environ.get('FLASK_HOST', '0.0.0.0')
    flask_port = int(os.environ.get('FLASK_PORT', '5000'))

    app.run(
        debug=flask_debug,
        host=flask_host,
        port=flask_port,
        use_reloader=False
    )


def start_email_service():
    """Start EmailService in main thread."""
    service = EmailService()
    service.start()


if __name__ == "__main__":
    # Ensure data directory exists
    ensure_data_dir()

    # Sync system environment variables into .env file
    # This allows Docker ENV vars to override .env settings
    sync_env_from_system()

    # Load environment variables from .env
    env_file = get_env_file()
    load_dotenv(env_file)

    # Initialize database
    db_url = get_database_url()
    engine = create_engine(db_url)
    init_db(engine)

    flask_thread = threading.Thread(target=start_flask, daemon=True, name="Flask")
    flask_thread.start()

    try:
        start_email_service()
    except KeyboardInterrupt:
        print("\nShutting down...")
