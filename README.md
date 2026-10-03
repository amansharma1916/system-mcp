# linux-mcp — a tiered, approval-gated MCP server for a Linux desktop

A local [Model Context Protocol](https://modelcontextprotocol.io) server that lets
an AI coding agent (opencode, Gemini CLI, Cline, or any other MCP client) work on
your Linux machine: read and write files, search them, inspect the system and its
processes, and — if you enable it — run arbitrary commands.

It speaks **STDIO** (the client launches it as a subprocess), so there is no port,
no public endpoint, and no network exposure.

## The tier model

Every tool belongs to exactly one tier, decided by its name. The tier decides
whether the call runs silently, needs your approval first, or is refused outright.

| Tier | Representative tools | Default behaviour |
| --- | --- | --- |
| `readonly` | `browse_files`, `read_file`, `file_info`, `checksum`, `search_files`, `search_content`, `list_tree`, `get_system_info`, `get_resource_usage`, `list_processes` | runs, audited |
| `write` | `open_application`, `write_file`, `edit_file`, `create_directory`, `move_path`, `copy_path`, `trash_path` | runs if the tier is enabled, audited |
| `system` | `kill_process` | **approval required**, audited |
| `destructive` | `delete_path`, `force_kill_process`, `run_command`, `run_shell` | **approval required**, audited |

Two rules make this load-bearing:

* **Deny by default.** A tool with no declared tier is refused, and the
  `destructive` tier is **disabled** in the shipped defaults, so `run_command`
  and `run_shell` cannot execute at all until you add `destructive` to
  `policy.enabled_tiers`.
* **Approval fails closed.** A confirming tool opens a desktop dialog (`zenity`)
  naming the exact action. No dialog — no display, no `zenity`, a timeout, an
  unexpected exit status — means the action is **refused**, never allowed.

Every call, allowed or refused, is appended to an audit log.

## Honest scope

This server can run arbitrary commands as your user. That is the point, and it is
also the risk: any text the model reads — a web page, a file, a command's output —
can contain instructions aimed at the model. The approval dialog is the barrier
between that and your account. Keep `confirm_tiers` at `system` and `destructive`,
leave `remember_for_seconds` at `0`, and read the dialog before clicking Allow.

The server still **refuses to start as root**, never stores a password, and never
escalates privileges on its own: privileged work goes through `pkexec`, which
raises a real polkit prompt per action.

## Verified environment

Developed and tested on:

| | |
| --- | --- |
| OS | EndeavourOS (Arch-based, rolling) |
| Python | 3.14.7 (the server also supports 3.10+, which the SDK requires) |
| Desktop | GNOME on Wayland |
| MCP SDK | `mcp` 2.2.0 (the current stable line) |
| Client compatibility | Verified against a handshake-era client sending `protocolVersion: 2025-06-18` over STDIO, which is what Gemini CLI and Cline send today |

Nothing in the implementation depends on Arch or GNOME: distribution- and
desktop-specific choices live in the configuration file, not in the code.

## Requirements

* Linux desktop (X11 or Wayland)
* Python 3.10 or newer, with `venv`
* A graphical session for `open_application` to be useful (the server itself runs
  headless)

## Installation

```bash
cd ~/Projects/system-mcp

# A virtual environment is required: on Arch/EndeavourOS the system Python is
# externally managed and pip refuses to install into it.
python3 -m venv .venv

# Runtime dependencies (MCP SDK + PyYAML)
.venv/bin/pip install -r requirements.txt

# Optional: test dependencies (pytest) and the linter used during development
.venv/bin/pip install -r requirements-dev.txt
```

### Configure

Copy the documented example and edit it:

```bash
mkdir -p ~/.config/linux-mcp
cp config/config.example.yaml ~/.config/linux-mcp/config.yaml
$EDITOR ~/.config/linux-mcp/config.yaml
```

The server looks for configuration in this order:

1. the `--config PATH` command line option
2. the file named by the `LINUX_MCP_CONFIG` environment variable
3. `config/config.yaml` next to the source
4. `~/.config/linux-mcp/config.yaml`

Validate it without serving anything:

```bash
.venv/bin/python server.py --check
```

```text
Configuration is valid.
  file: /home/aman/.config/linux-mcp/config.yaml
  allowed directories (3):
    /home/aman/Documents
    /home/aman/Downloads
    /home/aman/Projects
  allowed applications (5), max_entries=500:
    brave -> /usr/bin/brave - Brave Browser [ok]
    code -> /usr/bin/code - Visual Studio Code [ok]
    files -> /usr/bin/nautilus - GNOME Files [ok]
    firefox -> /usr/bin/firefox - Firefox [ok]
    terminal -> /usr/bin/gnome-terminal - GNOME Terminal [ok]
```

`--check` exits non-zero if anything is wrong, so it also works as a pre-flight
## Project layout

```text
system-mcp/
├── server.py                  # Thin entry point; the client launches this
├── linux_mcp/
│   ├── cli.py                 # Argument parsing, root check, --check, run
│   ├── app.py                 # Builds the MCPServer and registers every tool
│   ├── config.py              # YAML loading + strict validation (fail closed)
│   ├── policy.py              # Tier definitions and the tool -> tier registry
│   ├── guard.py               # tier -> approval -> action -> audit, in one place
│   ├── approval.py            # zenity dialog, fail-closed
│   ├── audit.py               # Append-only JSONL log, 0600, hash-chained
│   ├── exec.py                # No-shell runner: timeout, tree-kill, truncation
│   ├── containment.py         # systemd-run --user --scope wrapper
│   ├── redaction.py           # Secret masking for anything logged
│   ├── security.py            # Canonicalisation, allowlists, symlink checks
│   ├── logging_setup.py       # stderr-only logging (stdout is the protocol wire)
│   ├── errors.py              # Typed error hierarchy -> friendly ToolError text
│   └── tools/
│       ├── filesystem.py      # browse_files
│       ├── applications.py    # open_application
│       ├── filesystem_read.py # read_file, file_info, checksum, search_*, list_tree
│       ├── filesystem_write.py# write_file, edit_file, mkdir, move, copy, trash, delete
│       ├── system.py          # system info, resource usage, process list, kill
│       ├── commands.py        # run_command, run_shell
│       ├── settings.py        # gsettings get/set/list
│       ├── audio.py           # volume and mute via wpctl or pactl
│       ├── notifications.py   # notify-send
│       ├── packages.py        # pacman/yay/flatpak, pkexec for privileged work
│       ├── services.py        # systemd unit list/status/control
│       ├── power.py           # lock, logout, suspend, hibernate, poweroff, reboot
│       ├── clipboard.py       # wl-clipboard or xclip
│       └── screenshots.py     # grim, scrot, or maim (blocked on GNOME Wayland)
├── config/config.example.yaml # Documented example configuration
├── tests/                     # 458 tests incl. real-STDIO integration tests
├── docs/superpowers/          # Design spec and implementation plans
├── requirements.txt           # mcp + PyYAML
└── requirements-dev.txt       # pytest, ruff
```

Only `app.py` and the modules under `linux_mcp/tools/` import the MCP SDK.
`policy`, `guard`, `approval`, `audit`, `exec`, `containment`, `redaction`,
`security`, and `config` are all SDK-free, so every security boundary is testable
without a client connection.

Tools contain no policy logic of their own. They resolve their paths, then call
`linux_mcp.guard.guarded`, which enforces the tier, requests approval when the
tier requires it, runs the action, and writes exactly one audit record.

## The tools

### `browse_files`

Description sent to the model (the allowlist is embedded at startup, so the
model always knows its boundaries):

> List files and directories inside an allowed Linux directory. This tool does
> not read file contents. Allowed directories: /home/aman/Documents,
> /home/aman/Downloads, /home/aman/Projects.

`path` must be an absolute directory path inside the allowlist (`~` is
expanded; relative paths are rejected with a message listing the allowed
directories). The structured reply contains `requested_path`, `path`,
`parent`, `allowed_directories`, `entries` (directories first, then symlinks,
then files), and `truncated` when the result was cut off at `max_entries`
(default 500). Each entry reports `name`, `path`, `type` (`directory`,
`file`, `symlink`, `other`), `size_bytes`, `modified`, `hidden`, and — for
symlinks — `symlink_target` plus `escapes_allowed_directories`, so the model
can see a link pointing at `/etc` without that link ever being followed.

### `open_application`

Description sent to the model:

> Launch an approved Linux desktop application from the configured application
> allowlist. Arbitrary commands are not supported. Allowed application names:
> brave, code, files, firefox, terminal.

`name` is matched case-insensitively against the allowlist keys. The launch is
a fixed `argv` from configuration, run with `shell=False`, `close_fds=True`,
`start_new_session=True`, and all three of the child's standard streams sent to
`DEVNULL` — so a launched application can neither consume the MCP protocol
stream nor read anything from the server. Names not in the allowlist are
refused with the full list of allowed names.

### Filesystem, system, and command tools

| Tool | Tier | What it does |
| --- | --- | --- |
| `read_file` | readonly | Read a text file, capped at `limits.max_read_bytes`, with `offset`/`limit_bytes` |
| `file_info` | readonly | Type, size, mode, owner, group, timestamps, MIME type |
| `checksum` | readonly | md5 / sha1 / sha256 / sha512, streamed |
| `search_files` | readonly | Glob match on names, under one allowed directory |
| `search_content` | readonly | Regex search of file contents, with an optional glob, skipping binaries |
| `list_tree` | readonly | Recursive listing with depth and entry caps; symlinks are not followed |
| `get_system_info` | readonly | Distribution, kernel, architecture, CPUs, uptime, load, user |
| `get_resource_usage` | readonly | Live load, memory, swap, disk, and the top memory consumers |
| `list_processes` | readonly | Processes with RSS and command line, filterable |
| `write_file` | write | Create or (with `overwrite=true`) replace a file; atomic replace |
| `edit_file` | write | Replace an exact snippet, refusing an ambiguous match unless `replace_all` |
| `create_directory` | write | Create a directory, optionally with parents |
| `move_path` | write | Move or rename; refuses to replace a directory |
| `copy_path` | write | Copy from the read directories into the write directories |
| `trash_path` | write | Reversible move to the XDG trash, with a `.trashinfo` record |
| `delete_path` | **destructive** | Permanent removal. Refuses a directory without `recursive=true`; refuses an allowlist root |
| `kill_process` | system | Send SIGTERM or another catchable signal, to your own processes only |
| `force_kill_process` | **destructive** | Send SIGKILL. No cleanup, no saved state |
| `run_command` | **destructive** | Run an executable with an explicit argv. No shell |
| `run_shell` | **destructive** | Run a script through `bash -lc`. The most powerful tool here |

All of them refuse a path outside their allowlist, and `write_allow` includes
`delete_path`, so it is the boundary that matters most. `delete_path`,
`force_kill_process`, `run_command`, and `run_shell` open an approval dialog
showing the exact action; `kill_process` does too, because the tier default
confirms `system`.

### Desktop, package, and power tools (Phase 2)

| Tool | Tier | What it does |
| --- | --- | --- |
| `get_setting` / `list_settings` | readonly | Read one gsettings key; list schemas or keys |
| `get_volume` | readonly | Default sink volume and mute state (`wpctl` or `pactl`) |
| `list_packages` / `search_packages` / `package_info` | readonly | Query `pacman`/`yay`/`flatpak` |
| `list_services` / `service_status` | readonly | List systemd units; show one unit's status |
| `get_clipboard` | readonly | Read the clipboard (`wl-clipboard` or `xclip`) |
| `send_notification` | write | Desktop notification via `notify-send` |
| `set_clipboard` | write | Replace the clipboard |
| `take_screenshot` | write | Capture to a PNG (`grim`/`scrot`/`maim`) |
| `set_setting` | system | Write a gsettings key |
| `set_volume` / `mute_audio` | system | Change volume (0–150%) or mute |
| `start_service` / `stop_service` / `restart_service` | system | Control systemd units |
| `lock_screen` / `end_session` / `suspend_system` | system | Session and suspend actions |
| `install_package` / `remove_package` / `update_system` | **destructive** | Package changes |
| `shutdown_system` / `reboot_system` / `hibernate_system` | **destructive** | Power actions |

Privileged operations (packages, and `system`-scope services) go through
`pkexec`, which raises its own polkit password prompt. The server never sees or
stores a password. `power.allow` gates which power actions are permitted at all,
independently of the tier gate, so locking can be allowed while shutdown is not.

Some Phase 2 tools need desktop helpers that are not installed everywhere:
`wl-clipboard`, `grim`/`scrot`/`maim`, and `wpctl`/`pactl`. When the required
program is missing the tool returns a precise "requires the program X" error
rather than failing obscurely.

### Known platform limitations

* **`take_screenshot` does not work on GNOME Wayland.** Mutter implements
  neither the `wlr-screencopy` protocol that `grim` needs nor an unrestricted
  `org.gnome.Shell.Screenshot` (GNOME denies it to clients that are not the
  shell). This is a deliberate upstream restriction, not a bug here: the tool
  detects GNOME Wayland and returns an explanation naming the desktop's own
  Print Screen shortcut, rather than surfacing a cryptic protocol error. It
  works on GNOME/X11 and on compositors that permit programmatic capture.
* **`grim` cannot be used on GNOME at all**, for the same reason.
* **`wl-copy` forks a background process** that owns the clipboard. The runner
  has a `capture_output=False` mode for exactly this case, because a captured
  pipe stays open in the forked child and reading until EOF would block after
  the command had already finished.

## Connecting an MCP client

The generic registration every client needs is:

```json
{
  "mcpServers": {
    "linux-system": {
      "command": "/home/aman/Projects/system-mcp/.venv/bin/python",
      "args": ["/home/aman/Projects/system-mcp/server.py"],
      "env": {
        "LINUX_MCP_CONFIG": "/home/aman/.config/linux-mcp/config.yaml"
      }
    }
  }
}
```

Always point `command` at the **virtual environment's** interpreter: the MCP
SDK lives in `.venv`, not in the system Python.

### Gemini CLI

Add the server to `~/.gemini/settings.json` (user scope):

```json
{
  "mcpServers": {
    "linux-system": {
      "command": "/home/aman/Projects/system-mcp/.venv/bin/python",
      "args": ["/home/aman/Projects/system-mcp/server.py"],
      "env": { "LINUX_MCP_CONFIG": "/home/aman/.config/linux-mcp/config.yaml" }
    }
  }
}
```

Or with the CLI (use `-s user` when running from your home directory):

```bash
gemini mcp add -s user \
  -e LINUX_MCP_CONFIG=/home/aman/.config/linux-mcp/config.yaml \
  linux-system -- /home/aman/Projects/system-mcp/.venv/bin/python \
  /home/aman/Projects/system-mcp/server.py
```

**Important:** Gemini CLI only starts STDIO servers when it trusts the working
directory. If the server shows as *disconnected*, run `gemini trust` in the
project folder and restart — this is the most common cause of "my MCP server
won't connect".

### Cline (VS Code)

Edit
`~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
and add the same `mcpServers` block inside the existing `"mcpServers"` object.
Optionally add `"autoApprove": []` to keep every `browse_files` /
`open_application` call behind a manual approval prompt (recommended), and
restart Cline after editing.

### Verifying the connection

Any of these confirms the server speaks MCP correctly:

```bash
# Validate configuration without serving
.venv/bin/python server.py --check

## Testing

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest tests/ -v
```

193 tests existed before this expansion; the suite is now **458 tests**, all
passing, covering the original security boundaries and the tier, approval, audit,
execution, write-path, desktop, package, service, power, clipboard, and
screenshot policies.

| Area | Covered |
| --- | --- |
| `test_security.py` | traversal (`../`, absolute escapes, encoded names), symlink escapes (link, link-then-rename, directory links), non-directory roots, missing/empty config roots |
| `test_security_write.py` | write traversal including past a non-existent directory, symlink-parent escape, creating in a new subdirectory, relative paths |
| `test_config.py` | strict schema, unknown keys rejected, missing executables marked unavailable, `enabled: false`, `~`/`$VAR` expansion, malformed YAML, every-directory-missing fatal error |
| `test_config_policy.py` | new sections parsed, safe defaults, unknown tiers fatal, `write_allow ⊆ read_allow`, invalid containment mode fatal |
| `test_policy.py` | tier resolution, undeclared tool refused, disabled tier refused, confirmation independent of enablement |
| `test_approval.py` | allow, deny, timeout, missing `zenity`, no display, unexpected status, and that none of them fail open |
| `test_audit.py` | append + fsync, `0600`/`0700`, rotation, chain continuity, tamper detection, redaction |
| `test_exec.py` | no shell, non-zero exit, timeout with process-group kill, UTF-8-safe truncation, pkexec ordering, containment argv |
| `test_containment.py` | wrapper argv, defaults, fail-closed when `systemd-run` is missing |
| `test_guard.py` | tier gate, approval, denial without executing, error audit, redaction, undeclared tool refused |
| `test_tools_filesystem_read.py` | reading, truncation, metadata, hashing, name and content search, tree listing without following symlinks |
| `test_tools_filesystem_write.py` | create/overwrite rules, edits, moves, copies, trash with collisions, recursive-delete guard, allowlist-root refusal |
| `test_tools_system.py` | system info, resource usage, process listing and filtering, signal ownership rules, ignoring SIGTERM |
| `test_tools_commands.py` | gating switches, argv building, cwd validation, timeout clamping and firing, shell pipes |
| `test_tools_settings.py` | schema/key validation, GVariant round-trip, flag-like values refused |
| `test_tools_audio.py` | wpctl and pactl parsing, volume bounds, mute/toggle flags, no-mixer error |
| `test_tools_notifications.py` | argv construction with the `--` guard, urgency and expiry validation |
| `test_tools_packages.py` | package-name validation, argv per action and backend, cascade flags, escalation, auto backend |
| `test_tools_services.py` | unit listing and parsing, scope flags, escalation rules, non-zero status tolerated |
| `test_tools_power.py` | `power.allow` gating, action-to-command mapping, logout fallbacks |
| `test_tools_clipboard.py` | Wayland and X11 backends, empty clipboard, size caps |
| `test_tools_screenshots.py` | tool selection, destination containment, refuse to overwrite, the GNOME Wayland refusal |
| `test_filesystem.py` | valid browsing, ordering, hidden entries, `max_entries` truncation, nonexistent directory, refused paths, symlinks described but never followed |
| `test_applications.py` | allowlisted launch (real subprocess), unknown name refused, unavailable executable handled, fixed-argv only, arbitrary command strings rejected, full tool surface |
| `test_logging_setup.py` | stderr-only logging, stdout untouched, level control |
| `test_stdio_integration.py` | full subprocess STDIO handshake (`initialize` → `initialized` → `tools/list` → `tools/call`), legacy `protocolVersion: 2025-06-18`, security refusals over the wire, **a denied approval blocking execution and being audited**, and a read-only call being audited |

Lint with `ruff check .` (clean as of the last run).

## Security design

* **Allowlist, not blacklist.** Every tool starts from "nothing is permitted";
  configuration grants exactly what the user lists. Reads and writes have
  separate allowlists, and `write_allow` must be a subset of `read_allow`.
* **Canonicalisation before every decision.** Paths are resolved with
  `Path.resolve()` and must remain inside a resolved allowed directory; `..`
  components therefore cannot escape. For writes, the path is normalised first
  (so `allowed/newdir/../../outside/x` becomes `outside/x` before any decision),
  then anchored on its nearest existing ancestor, which must be allowed.
* **Symlinks are described, never followed.** Browsing uses `os.scandir` with
  `follow_symlinks=False` everywhere; a symlink's target is read with
  `os.readlink` for information only, and flagged when it resolves outside the
  allowlist. A symlink inside `~/Downloads` pointing at `/etc` cannot be used
  as a doorway, for reading or for writing.
* **No shell for typed tools.** Applications launch as a fixed `argv` built only
  from the configuration, with `shell=False`. `run_command` also takes an
  explicit argv. `run_shell` is the single exception and is a separate,
  tier-`destructive`, per-call-approved tool built as `["bash", "-lc", script]`
  — an argv, never a string interpolated into one.
* **Every command is contained.** Commands run inside a transient
  `systemd-run --user --scope` with memory and CPU caps and a guaranteed
  whole-tree kill. If the wrapper is unavailable the call fails closed.
* **Not root, ever.** `geteuid() == 0` aborts startup before the server is
  built, so `sudo python server.py` fails loudly. Privileged work goes through
  `pkexec`, which raises a real polkit prompt; no password is stored or cached.
* **Fail closed.** Unknown configuration keys, malformed YAML, an undeclared
  tool, a disabled tier, or a config in which every allowed directory is missing
  all stop the action rather than weakening the policy. Approval failures deny.
* **Audited before returning.** Every call writes one JSONL record to the audit
  log, flushed and `fsync`-ed before the tool returns. Records are `0600` in a
  `0700` directory and hash-chained, so deleting or editing a line is detectable
  with `verify_chain()`. Arguments are redacted; file contents are never logged.
* **Least-privilege child processes.** Launched apps get `DEVNULL` on stdin/
  stdout/stderr, a fresh session, and closed file descriptors.

## Logging

Diagnostics go to **stderr** only — stdout carries nothing but MCP protocol
messages, so logging can never corrupt the stream. Startup, tool invocations,
requested paths, launch attempts, and errors are logged at `INFO`/`WARNING`
(file contents and environment values are never logged). Control verbosity
with `--log-level DEBUG|INFO|WARNING|ERROR` or the `LINUX_MCP_LOG_LEVEL`
environment variable.

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| Client shows the server as disconnected | Folder not trusted in Gemini CLI (`gemini trust`); wrong `command` — must be `.venv/bin/python`; config path wrong — run `--check` with the same `LINUX_MCP_CONFIG` |
| `Configuration is invalid` at startup | Run `.venv/bin/python server.py --check` — it prints the offending directory, application, or key |
| `Refusing to run as root` | You started it with `sudo`; start it as your normal user |
| `browse_files` returns *Permission denied: … outside the configured allowed directories* | Working as intended — add the directory to `directories.allow` and restart the client |
| `open_application` says *is not in the application allowlist* | Add the name to `applications.allow` in the config; the error lists every allowed name |
| Application is allowlisted but *cannot be launched* | Its `command` executable is missing or not executable — `--check` marks it `UNAVAILABLE` with the reason |
| Nothing on stdout, no MCP traffic | Another handler is writing to stdout; this project routes all logs to stderr, but a custom change could break the wire |

## Roadmap

Phases 1 and 2 are implemented: the tiered foundation, filesystem, system,
process, and command tools, plus desktop settings, audio, notifications,
packages, services, power, clipboard, and screenshots.

**Phase 3 — web and peripherals** remains, with its configuration sections
already parsed and validated:

* `fetch_url`, `web_search`, `open_url`, `download_file`
* network information and Wi-Fi (`nmcli` is already present)
* storage (disk usage, mounts, eject)
* scheduling (cron, systemd user timers, `.desktop` entries)
* media control (`playerctl`) and input injection (`ydotool`/`wtype`)
* brightness (`brightnessctl`)

Adding a capability means writing one module in `linux_mcp/tools/`, giving the
tool a tier in `linux_mcp/policy.py`, and listing its `register` in
`linux_mcp/tools/__init__.py`. A tool with no declared tier is refused, and a
test asserts that registration and the tier registry agree exactly, so a new
capability cannot accidentally ship unguarded or half-wired.

## Definition of Done — status

1. ✅ Server starts on Linux (`python server.py --check` validates; serving verified live)
2. ✅ MCP client connects over STDIO (real-subprocess integration tests, legacy handshake verified)
3. ✅ Tools are discoverable (`tools/list` tested over the wire, exact surface asserted)
4. ✅ `browse_files` browses configured directories (verified live on this machine)
5. ✅ `browse_files` cannot escape its boundaries (traversal, `/etc`, symlinks — all refused)
6. ✅ `open_application` launches configured applications (live GNOME app launch verified)
7. ✅ Typed tools never use a shell; `run_shell` is a separate, per-call-approved tool
8. ✅ Runs without root (refuses to start as root by design; escalation only via `pkexec`)
9. ✅ Errors handled cleanly (typed error hierarchy → readable `ToolError` text, never stack traces)
10. ✅ Every tool declares a tier; an undeclared tool is refused
11. ✅ `system` and `destructive` tools require approval, and approval failures deny
12. ✅ Every call is written to a hash-chained, `0600` audit log before returning
13. ✅ Write paths are resolved and contained, including creation in new subdirectories
14. ✅ Commands run in a `systemd-run` scope with memory/CPU caps and whole-tree kill
15. ✅ Tests cover the boundaries (458 passing, including a denied approval over real STDIO)
16. ✅ Desktop, package, service, power, clipboard, and screenshot tools (Phase 2)
17. ✅ Privileged operations go through pkexec; no password is stored or cached
18. ✅ Registration and the tier registry are asserted to agree exactly
19. ✅ This README documents installation, configuration, running, and client connection
# Run the same real-STDIO handshake the clients perform (part of the test suite)
.venv/bin/python -m pytest tests/test_stdio_integration.py -v
```

In the client itself, the tool list should show `browse_files` and
`open_application`; if it shows them but calls fail, check the server's stderr
output (see *Logging*) and re-run `--check`.
`DEVNULL` — so a launched application can neither consume the MCP protocol
stream nor read anything from the server. Names not in the allowlist are
refused with the full list of allowed names.
step in a script.