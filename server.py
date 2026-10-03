#!/usr/bin/env python3
"""Entry point for the Linux system MCP server.

An MCP client launches this file as a subprocess and talks to it over STDIO::

    python /home/aman/Projects/system-mcp/server.py

Run ``python server.py --check`` to validate the configuration without serving,
and ``python server.py --help`` for the available options.
"""

from linux_mcp.cli import main

if __name__ == "__main__":
    raise SystemExit(main())