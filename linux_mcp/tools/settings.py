"""Desktop settings through ``gsettings``.

``gsettings`` covers a large share of GNOME configuration: theme, wallpaper,
fonts, keyboard, power, idle, clock, and more. Reads are tier ``readonly``;
writes are tier ``system`` and therefore require a per-call approval, because a
mis-set key can leave the desktop in an awkward state.

Schema and key names are validated to a safe character set and may not start
with a dash, so a model cannot turn a key into a command-line option.
"""

from __future__ import annotations

import re
from typing import Annotated

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from linux_mcp.config import Config
from linux_mcp.errors import InvalidPathError, LinuxMCPError
from linux_mcp.guard import GuardContext, guarded
from linux_mcp.logging_setup import get_logger
from linux_mcp.tools._common import require_program, run_program

logger = get_logger("tools.settings")

_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
"""A valid gsettings schema or key name."""


class SettingResult(BaseModel):
    """The result of reading or writing one setting."""

    schema_name: str = Field(
        description="The gsettings schema, for example org.gnome.desktop.interface."
    )
    key: str = Field(description="The key within the schema.")
    value: str = Field(
        description=(
            "The value as a GVariant literal. Strings are quoted, for example "
            "'prefer-dark'."
        )
    )


class SettingsListResult(BaseModel):
    """The result of listing schemas or the keys within one schema."""

    scope: str = Field(description="Either 'schemas' or the schema whose keys were listed.")
    entries: list[str] = Field(description="Schema names or key names.")
    total: int = Field(description="How many entries were returned.")


def _validate_name(value: str, *, what: str) -> str:
    if not isinstance(value, str) or not _NAME_PATTERN.match(value):
        raise InvalidPathError(
            f"Invalid {what} name {value!r}. Expected letters, digits, dots, "
            "dashes or underscores, starting with a letter or digit, for example "
            "'org.gnome.desktop.interface' or 'color-scheme'."
        )
    return value


def _validate_value(value: str) -> str:
    if "\x00" in value or "\n" in value or "\r" in value:
        raise InvalidPathError("A setting value must not contain NUL bytes or line breaks.")
    if value.startswith("--"):
        raise InvalidPathError(
            f"Setting value {value!r} must not start with '--'. Pass a GVariant "
            "literal, for example \"'prefer-dark'\" for a string or 50 for a number."
        )
    return value


def read_setting(schema: str, key: str) -> SettingResult:
    """Read one key from a gsettings schema."""
    schema = _validate_name(schema, what="schema")
    key = _validate_name(key, what="key")
    gsettings = require_program("gsettings", purpose="Reading a desktop setting")
    output = run_program(
        [gsettings, "get", schema, key],
        purpose=f"gsettings get {schema} {key}",
    )
    return SettingResult(schema_name=schema, key=key, value=output.strip())


def write_setting(schema: str, key: str, value: str) -> SettingResult:
    """Write one key and read it back so the caller sees the stored value."""
    schema = _validate_name(schema, what="schema")
    key = _validate_name(key, what="key")
    value = _validate_value(value)
    gsettings = require_program("gsettings", purpose="Changing a desktop setting")
    run_program(
        [gsettings, "set", schema, key, value],
        purpose=f"gsettings set {schema} {key}",
    )
    return read_setting(schema, key)


def collect_settings(schema: str | None = None) -> SettingsListResult:
    """List every schema, or every key within *schema*."""
    gsettings = require_program("gsettings", purpose="Listing desktop settings")
    if schema is None:
        output = run_program([gsettings, "list-schemas"], purpose="gsettings list-schemas")
        entries = sorted(line.strip() for line in output.splitlines() if line.strip())
        return SettingsListResult(scope="schemas", entries=entries, total=len(entries))

    schema = _validate_name(schema, what="schema")
    output = run_program(
        [gsettings, "list-keys", schema],
        purpose=f"gsettings list-keys {schema}",
    )
    entries = sorted(line.strip() for line in output.splitlines() if line.strip())
    return SettingsListResult(scope=schema, entries=entries, total=len(entries))


def register(server: MCPServer, config: Config, context: GuardContext) -> None:
    """Declare the gsettings tools on *server*."""

    @server.tool(
        title="Read a desktop setting",
        description=(
            "Read one key from a GNOME gsettings schema. Values are GVariant "
            "literals; strings come back quoted, for example 'prefer-dark'. "
            "Examples: org.gnome.desktop.interface / color-scheme, "
            "org.gnome.desktop.background / picture-uri."
        ),
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    def get_setting(
        schema: Annotated[str, Field(description="gsettings schema, for example org.gnome.desktop.interface.")],
        key: Annotated[str, Field(description="Key within the schema, for example color-scheme.")],
    ) -> SettingResult:
        """Read one desktop setting."""
        logger.info("get_setting(schema=%r, key=%r)", schema, key)
        try:
            return guarded(
                context,
                tool="get_setting",
                arguments={"schema": schema, "key": key},
                action=lambda: read_setting(schema, key),
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Change a desktop setting",
        description=(
            "Write one key in a GNOME gsettings schema. The value must be a valid "
            "GVariant literal exactly as gsettings expects: \"'prefer-dark'\" for a "
            "string, \"true\" for a boolean, \"50\" for a number. Requires approval. "
            "Read the key first to see the exact format it uses."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    def set_setting(
        schema: Annotated[str, Field(description="gsettings schema to change.")],
        key: Annotated[str, Field(description="Key to change.")],
        value: Annotated[
            str,
            Field(description="GVariant literal, for example \"'prefer-dark'\" or \"true\"."),
        ],
    ) -> SettingResult:
        """Change one desktop setting. Requires approval."""
        logger.info("set_setting(schema=%r, key=%r)", schema, key)
        try:
            return guarded(
                context,
                tool="set_setting",
                arguments={"schema": schema, "key": key, "value": value},
                summary=f"Change {schema} {key}",
                details=f"gsettings set {schema} {key} {value}",
                action=lambda: write_setting(schema, key, value),
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="List desktop schemas or keys",
        description=(
            "With no schema, list every gsettings schema on the system. With a "
            "schema, list its keys. Use this to discover what can be read or "
            "changed."
        ),
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    def list_settings(
        schema: Annotated[
            str | None,
            Field(description="Schema whose keys to list; omit to list all schemas."),
        ] = None,
    ) -> SettingsListResult:
        """List gsettings schemas, or the keys within one schema."""
        logger.info("list_settings(schema=%r)", schema)
        try:
            return guarded(
                context,
                tool="list_settings",
                arguments={"schema": schema},
                action=lambda: collect_settings(schema),
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc
