"""MailMind-AI entry point."""

import subprocess
import sys
from pathlib import Path


def install_dependencies():
    """Install required dependencies from requirements.txt."""
    requirements_file = Path(__file__).parent / "requirements.txt"

    if not requirements_file.exists():
        print("Warning: requirements.txt not found", file=sys.stderr)
        return

    print("Installing dependencies...")
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-q", "-r", str(requirements_file)
        ])
        print("Dependencies installed.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install dependencies: {e}", file=sys.stderr)
        sys.exit(1)


def check_dependencies():
    """Check if required packages are installed."""
    required = ["anthropic", "dotenv"]
    missing = []

    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)

    return len(missing) == 0


if __name__ == "__main__":
    if not check_dependencies():
        install_dependencies()

    sys.path.insert(0, str(Path(__file__).parent / "src"))

    from mailmind.__main__ import main
    sys.exit(main())
