# linux-mcp: Full System Control Expansion — Design

**Date:** 2026-09-15
**Status:** Approved (design reviewed in chat; decisions locked)
**Supersedes:** the "What it deliberately cannot do" and "Future expansion"
sections of `README.md`

---

## 1. Goal

Expand `linux-mcp` from two locked-down tools (`browse_files`,
`open_application`) into a general-purpose local system control server: web and
local search, file read/write, system settings, package install/remove, power
and session control, and free-form command execution — while keeping a
human-approval gate on anything dangerous.

Success is: an MCP client can accomplish arbitrary local tasks, and every
destructive action requires a deliberate human "Allow".

## 2. Non-goals

- Running the server as root, or with stored/cached credentials.
- Password changes, user creation/deletion, or `chown`-style ownership changes.
- Disk partitioning, filesystem creation, or bootloader modification.
- Any action that cannot be attributed to a single user-visible approval.

## 3. Locked decisions

| # | Decision | Choice |
|---|---|---|
| D1 | Safety model | Tiered: T0 readonly → T1 write → T2 system → T3 destructive, with confirmation |
| D2 | Approval channel | Layered: MCP client approval UI as baseline **plus** a native `zenity` dialog for T2/T3; fail-closed |
| D3 | Command execution | Free-form argv (`run_command`) and free-form shell (`run_shell`), both T3 |
| D4 | Privileged operations | `pkexec` (polkit prompt) per action; never root, never stored credentials |
| D5 | Web search backend | DuckDuckGo HTML scrape, no API key (accepted brittleness) |
| D6 | Missing helper tools | Install as a documented setup step: `brightnessctl`, `wl-clipboard`, `grim`, `slurp`, `playerctl`, `ydotool`, `trash-cli` |
| D7 | Execution containment | Transient `systemd-run --user --scope` (own cgroup, caps, whole-tree kill) |
| D8 | Scope | Delivered in three phases |

## 4. Threat model

**Assets:** the user's account (`aman`), data under `/home/aman`, SSH/GPG keys,
browser sessions, the wider local network.

**Adversary:** primarily *indirect prompt injection*. The server reads untrusted
content (web pages via `fetch_url`/`web_search`, file contents via `read_file`,
command output via `run_command`). Any of that text can contain instructions
aimed at the model. A sufficiently persuasive injection can turn a read into an
execution.

**Consequences accepted by design:** free-form `run_command` plus a
scraping-based `web_search` is the highest-risk combination in this design. The
approval dialog is the *only* barrier between injected text and account
compromise. This is accepted and must not be weakened without revisiting D1–D3.

**Explicitly out of scope:** a local attacker who already has code execution as
`aman` (they can read the audit log, spoof dialogs, and signal the server).
Defending against that is not attempted.

### 4.1 Why the confirmation gate is load-bearing

With free-form argv, an allowlist of executables is meaningless (`bash -c` is
always reachable). Therefore the controls that actually matter are:

1. The **approval gate** (prevents, at human-decision time).
2. The **audit log** (records, after the fact — detective, not preventive).
3. **Containment** (bounds blast radius of a runaway or hostile process).

Nothing else in this design meaningfully constrains a confirmed `run_command`,
and the spec says so plainly rather than implying otherwise.

## 5. Architecture

### 5.1 New core modules (all SDK-free and unit-testable)

| Module | Responsibility |
|---|---|
| `linux_mcp/policy.py` | Tier definitions, per-tool tier registry, decision resolution (auto / confirm / refuse). Deny-by-default: a tool with no declared tier is refused. |
| `linux_mcp/approval.py` | The approval gate. Renders the action, drives `zenity`, enforces timeout, fails closed. Returns `ApprovalDecision`. |
| `linux_mcp/audit.py` | Append-only JSONL audit log with optional hash chaining, 0600 permissions, size rotation, and argument redaction. |
| `linux_mcp/exec.py` | Safe subprocess execution: argv construction, timeout, process-group kill, output truncation, env scrubbing, `pkexec` wrapping. |
| `linux_mcp/containment.py` | Builds the `systemd-run --user --scope` wrapper when containment is enabled. |
| `linux_mcp/guard.py` | The single composition point every tool calls: resolve tier → refuse if disabled → request approval if required → run the action → write the audit record. Tools contain no policy logic of their own. |
| `linux_mcp/redaction.py` | Shared secret-redaction helpers (env values, tokens, password-looking args). |

### 5.2 Extended existing modules

- `config.py` — new validated sections: `policy`, `filesystem`, `commands`,
  `web`, `packages`, `power`, plus `settings`, `network`, `storage`, `media`,
  `input` in later phases.
- `security.py` — add `canonicalize_write_path()` (resolve-then-verify against a
  **separate** `write_allow` list, including for paths that do not exist yet),
  and `normalize_argv()` for command validation.
- `errors.py` — add `UndeclaredToolError`, `TierDisabledError`,
  `ApprovalDeniedError`, `ApprovalUnavailableError`, `CommandTimeoutError`,
  `CommandFailedError`, `OutputLimitError`, `PrivilegeEscalationError`.

### 5.3 Tool modules

Phase 1: `filesystem_write.py`, `search.py`, `system_info.py`, `processes.py`,
`commands.py`.
Phase 2: `settings.py`, `packages.py`, `power.py`, `clipboard.py`,
`screenshots.py`.
Phase 3: `web.py`, `network.py`, `storage.py`, `scheduling.py`, `media.py`,
`input.py`.

Every module exposes `register(server, config)` and is listed in
`linux_mcp/tools/__init__.py::_REGISTRARS`.

### 5.4 Dependency direction

```
tools/*  →  guard  →  policy, approval, audit, exec, containment, security, config, errors
                                        ↑
                          (no MCP imports below this line)
```

`guard`, `policy`, `approval`, `audit`, `exec`, `containment`, `security`, and
`redaction` must not import `mcp`. Tools translate the typed errors `guard`
raises into MCP `ToolError` results. This preserves the project's existing
property that security boundaries are testable without a client connection.

## 6. Tier model

| Tier | Name | Examples | Default |
|---|---|---|---|
| 0 | `readonly` | browse, read_file, search, system_info, process list, fetch_url | auto (audited) |
| 1 | `write` | write_file, edit_file, mkdir, move, copy, download_file | auto if enabled (audited) |
| 2 | `system` | gsettings set, audio, install/remove package, service start/stop, wifi connect | confirm + audit |
| 3 | `destructive` | permanent delete, SIGKILL, shutdown/reboot, uninstall, `run_command`, `run_shell` | confirm + audit |

Rules:

- A tool call resolves to exactly one tier via an explicit registry entry keyed
  by tool name. **Missing registry entry ⇒ refuse** (deny-by-default).
- `policy.enabled_tiers` gates which tiers may execute at all. A disabled tier
  yields `TierDisabledError` naming the tier and how to enable it.
- `policy.confirm_tiers` decides which tiers require approval. Enabling a tier
  does not imply confirming it; both are explicit.
- Approval cannot be downgraded by the model. There is no tool argument that
  changes tier or bypasses confirmation.

## 7. Approval flow

```
tool call
  → policy.resolve(tool_name) → (tier, enabled?, confirm?)
      → disabled            → TierDisabledError
      → confirm not required → execute → audit(decision="auto")
      → confirm required
          → approval.request(action)
              → Allow   → execute → audit(decision="approved")
              → Deny    → ApprovalDeniedError → audit(decision="denied")
              → timeout → ApprovalDeniedError → audit(decision="timeout")
              → dialog unavailable → ApprovalUnavailableError → audit(decision="unavailable")
```

### 7.1 `ApprovalDecision`

```python
@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    allowed: bool
    mechanism: Literal["zenity"] | None
    reason: Literal["allow", "deny", "timeout", "unavailable", "disabled"]
    elapsed_seconds: float
```

### 7.2 Dialog contract

Rendered with `zenity --question`:

- **Title:** `linux-mcp approval required`
- **Heading:** the tool name and tier, e.g. `run_command (destructive)`
- **Exact action:** the fully resolved argv, `cwd`, and environment additions,
  shown verbatim and never truncated.
- **Untrusted note:** the model's stated reason, explicitly labelled
  `Model's reason (untrusted): …`.
- **Buttons:** `Allow` / `Deny`, default **Deny** (`--default-cancel`).
- **Timeout:** `policy.approval.timeout_seconds` (default 60) ⇒ treated as Deny.

### 7.3 Fail-closed rules

Deny (never allow) when any of: `zenity` missing; `DISPLAY` and
`WAYLAND_DISPLAY` both unset; non-zero/spawn failure; unparseable exit status;
timeout; mechanism disabled in config but a tier requires it.

### 7.4 No automatic remembering

`policy.approval.remember_for_seconds` defaults to `0` (always ask). A non-zero
value is permitted but is strongly discouraged for T3 and must be logged.

## 8. Audit log

- **Format:** one JSON object per line (JSONL).
- **Location:** `policy.audit.path`, default
  `~/.local/state/linux-mcp/audit.jsonl`.
- **Permissions:** file `0600`, parent directory `0700`; enforced on open.
- **Chaining:** each record carries `prev_hash` (SHA-256 of the previous line's
  canonical bytes) so truncation or edits are detectable offline.
- **Rotation:** when the file exceeds `policy.audit.max_bytes` (default 10 MiB),
  rotate to `audit.jsonl.1` (single generation; the previous `.1` is replaced).
- **Redaction:** argument values matching secret patterns, environment variables
  whose names match `*TOKEN*`, `*KEY*`, `*SECRET*`, `*PASSWORD*`, and the
  `pkexec`/`sudo` password prompt are replaced with `[redacted]`. File contents
  are never logged.
- **Record shape:**

```json
{
  "ts": "2026-09-15T22:30:00.123456+00:00",
  "tool": "run_command",
  "tier": "destructive",
  "decision": "approved",
  "mechanism": "zenity",
  "arguments": {"argv": ["ls", "-la"], "cwd": "/home/aman"},
  "cwd": "/home/aman",
  "exit_code": 0,
  "duration_ms": 42,
  "outcome": "ok",
  "error": null,
  "prev_hash": "…",
  "hash": "…"
}
```

Writes are flushed and `fsync`-ed before the tool returns, so a crash cannot
lose the record of an executed action.

## 9. Execution & containment

### 9.1 `exec.run_argv()`

Responsibilities: build argv, choose the containment wrapper, run with no shell
by default, enforce timeout, kill the whole process group on timeout, truncate
output, capture exit status.

Signature:

```python
def run_argv(
    argv: Sequence[str],
    *,
    cwd: Path | None,
    env: Mapping[str, str] | None,
    timeout_seconds: float,
    max_output_bytes: int,
    contain: ContainmentMode,
    use_pkexec: bool = False,
) -> CommandResult
```

```python
@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: list[str]
    cwd: str | None
    exit_code: int | None
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    duration_ms: int
    timed_out: bool
```

Rules:

- Never `shell=True`. `run_shell` is implemented as
  `["bash", "-lc", script]` — an explicit argv, not a shell interpolation.
- `start_new_session=True`; on timeout `os.killpg` with `SIGTERM`, wait
  `policy.limits.kill_grace_seconds` (default 3), then `SIGKILL`.
- Environment is `os.environ` minus nothing by default, but with `pkexec` the
  environment is passed through the wrapper deliberately; secrets are never
  injected by the server.
- Output beyond `max_output_bytes` is truncated at a UTF-8 boundary;
  `stdout_truncated` reports it. Default limit
  `policy.limits.max_output_bytes` = 100000.
- Non-zero exit does **not** raise by default; the result carries the code. A
  `check: bool = False` parameter raises `CommandFailedError` when true.

### 9.2 Containment modes

```python
ContainmentMode = Literal["none", "systemd-scope"]
```

`systemd-scope` wraps: `systemd-run --user --scope --quiet --collect
-p MemoryMax=2147483648 -p CPUQuota=200% -- <argv>` (2 GiB and two cores by
default, from `commands.containment_memory_max_bytes` and
`commands.containment_cpu_quota`). If `systemd-run` is unavailable, the call
fails closed with a clear error rather than silently running uncontained.

### 9.3 Privilege escalation

- Root-only actions are invoked as `["pkexec", *argv]`, which raises a polkit
  authorization prompt naming the program.
- The server never accepts a password, never caches one, and refuses to start as
  root (existing `ensure_not_root()` is retained unchanged).
- `commands.allow_pkexec: false` refuses all escalation with
  `PrivilegeEscalationError`.

## 10. Configuration schema

Strict validation is retained: unknown keys are fatal, missing critical sections
are fatal, and the server never starts with a broader policy than written.

```yaml
policy:
  enabled_tiers: [readonly, write, system, destructive]
  confirm_tiers: [system, destructive]
  approval:
    mechanism: zenity          # zenity
    timeout_seconds: 60
    remember_for_seconds: 0
  audit:
    enabled: true
    path: ~/.local/state/linux-mcp/audit.jsonl
    max_bytes: 10485760
  limits:
    default_timeout_seconds: 30
    max_timeout_seconds: 600
    kill_grace_seconds: 3
    max_output_bytes: 100000
    max_read_bytes: 1000000
    rate_limit_per_minute: 60

filesystem:
  read_allow: [~/Documents, ~/Downloads, ~/Projects]
  write_allow: [~/Downloads, ~/Projects]      # must be a subset of read_allow
  follow_symlinks: false

commands:
  run_command_enabled: true
  run_shell_enabled: true
  containment: systemd-scope                  # none | systemd-scope
  containment_memory_max_bytes: 2147483648    # 2 GiB
  containment_cpu_quota: "200%"               # two cores
  allow_pkexec: true

web:
  enabled: true
  search_provider: duckduckgo                 # duckduckgo | none
  max_fetch_bytes: 2000000

packages:
  backend: pacman                             # pacman | yay | flatpak | auto
  use_pkexec: true

power:
  allow: [lock, logout, suspend]              # destructive actions opt-in:
  # add shutdown, reboot, hibernate explicitly
```

Backward compatibility: the existing top-level `directories` and
`applications` keys remain valid and keep their current semantics. When
`filesystem` is absent, `directories.allow` supplies both `read_allow` and
`write_allow`; when present it takes precedence. The Phase-1 baseline does not
change the meaning of any existing key.

## 11. Capability catalogue

### Phase 1 — foundation + core
| Tool | Tier |
|---|---|
| `read_file` | T0 |
| `search_files`, `search_content`, `file_info`, `checksum`, `list_tree` | T0 |
| `get_system_info`, `get_resource_usage`, `list_processes` | T0 |
| `write_file`, `edit_file`, `create_directory`, `move_path`, `copy_path` | T1 |
| `trash_path` (moves to trash, reversible) | T1 |
| `delete_path` (permanent, irreversible) | T3 |
| `kill_process` (SIGTERM) | T2 |
| `force_kill_process` (SIGKILL) | T3 |
| `run_command` | T3 |
| `run_shell` | T3 |

> **Tier granularity rule.** A tool's tier is determined **solely by its name**;
> there is no per-argument tier. Where one capability has a safe and a dangerous
> form, they are **two tools** with distinct names (`trash_path` vs
> `delete_path`, `kill_process` vs `force_kill_process`) so that the registry,
> the audit record, and the approval dialog always agree on exactly one tier.

### Phase 2 — system control
`get_setting`/`set_setting` (gsettings), `list_settings`, audio
(`get_volume`/`set_volume`/`mute`), display info and mode, wallpaper/theme,
`send_notification`, package `search`/`list`/`info`/`install`/`remove`/`update`,
services (`list`/`status`/`start`/`stop`/`restart`), power
(`lock`/`logout`/`suspend`/`shutdown`/`reboot`/`hibernate`), clipboard
get/set, screenshot.

### Phase 3 — web & peripherals
`fetch_url`, `web_search`, `open_url`, `download_file`, network info, wifi
list/connect/disconnect, storage (disk usage, mounts, eject), scheduling (cron,
systemd user timers, `.desktop` entries), media control, input injection
(type/keys/mouse), brightness.

## 12. Security invariants (must hold after every phase)

1. The server refuses to start as root.
2. Every path from the model is fully resolved and verified against an allowlist
   **before** use — for reads *and* writes.
3. No typed tool uses a shell. `run_shell` is an explicit, tier-3, confirmed
   tool; it is not a convenience wrapper others call.
4. A tool with no declared tier is refused.
5. Every executed action is audited before the tool returns.
6. Confirmation failures (missing dialog, timeout, no display) deny, never allow.
7. File contents and secret-looking arguments are never logged.
8. Output and file reads are size-limited to protect the model's context and the
   server's memory.

## 13. Testing strategy

Extends the existing 193-test suite. New coverage:

| Area | Cases |
|---|---|
| `policy` | tier resolution; refuse undeclared tool; disabled tier; confirm vs auto; no model-controlled tier change |
| `approval` | allow; deny; timeout; zenity missing; no display; non-zero exit; unparseable status; never fails open |
| `audit` | append + fsync; 0600/0700 perms; rotation; hash chain detects tampering; redaction of tokens/keys/passwords; file contents never present |
| `exec` | success; non-zero exit; timeout kills process group; truncation at UTF-8 boundary; no shell by default; `run_shell` builds explicit argv; cwd validation; containment wrapper argv |
| write-path security | traversal; symlink escape on write; create inside allowlist; refuse create outside; refuse when `write_allow` empty; overwrite policy |
| `run_command`/`run_shell` | always tier 3; refused when tier disabled; approval-denied path; pkexec wrapping; pkexec disabled |
| integration (real STDIO) | tools/list shows new tools; an approval-gated call denied over the wire; audit line written for a denied call |

Tests must not spawn real dialogs or real `pacman`. `approval`, `exec`, and
`containment` take injectable runners so tests substitute fakes.

## 14. Phasing & rollout

Each phase is independently shippable, fully tested, and documented before the
next begins.

- **Phase 1:** policy, approval, audit, exec, containment, config, write-path
  security, and the tools listed in §11 Phase 1.
- **Phase 2:** settings, packages, power, clipboard, screenshots.
- **Phase 3:** web, network, storage, scheduling, media, input.

Phase 2/3 depend on the documented helper-tool install (D6). Until a helper is
installed, its tool returns a precise "required program X is not installed"
error rather than failing obscurely.

## 15. Open risks

1. **Prompt injection → RCE.** Highest risk; mitigated only by the approval
   dialog. Accepted under D1–D3.
2. **DuckDuckGo scraping brittleness.** The search tool may break when markup
   changes. Isolated behind a provider interface so it can be swapped.
3. **Approval fatigue.** Repeated dialogs train the user to click Allow. Design
   mitigations: dialogs show the exact argv, default to Deny, and never
   auto-remember by default.
4. **GNOME Wayland limits.** Display control, input injection, and some settings
   are restricted under Wayland; some Phase 2/3 tools will be partial or require
   helper daemons. Handled per-tool with clear capability errors.
5. **`systemd-run` absent.** Containment fails closed; documented.
