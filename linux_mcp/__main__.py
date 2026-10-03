"""Allow ``python -m linux_mcp`` as an alternative to ``python server.py``."""

from linux_mcp.cli import main

if __name__ == "__main__":
    raise SystemExit(main())