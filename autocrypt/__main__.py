"""Allow ``python -m autocrypt`` to run the CLI."""
from autocrypt.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
