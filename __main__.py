import os
import threading
from dotenv import load_dotenv

from sqlalchemy import create_engine
from Entities import init_db
from Webservice import app
from EmailService import EmailService


def start_flask():
    """Start Flask web server in separate thread."""
    load_dotenv()

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
    engine = create_engine("sqlite:///storage.db")
    init_db(engine)

    flask_thread = threading.Thread(target=start_flask, daemon=True, name="Flask")
    flask_thread.start()

    try:
        start_email_service()
    except KeyboardInterrupt:
        print("\nShutting down...")
