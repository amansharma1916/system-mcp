"""A local, deliberately small MCP server for controlling a Linux desktop.

The package is split so that security policy is testable without the MCP SDK:

* :mod:`linux_mcp.errors` - typed, model-friendly failures.
* :mod:`linux_mcp.security` - path canonicalisation and allowlist enforcement.
* :mod:`linux_mcp.config` - configuration loading and validation.
* :mod:`linux_mcp.logging_setup` - stderr-only diagnostic logging.
* :mod:`linux_mcp.tools` - the MCP tools (``browse_files``, ``open_application``).
* :mod:`linux_mcp.app` - assembles the MCP server object.
* :mod:`linux_mcp.cli` - command line entry point used by ``server.py``.

Nothing in this package imports ``sudo``, a shell, or starts processes other
than the explicitly allowlisted desktop applications.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]