#!/usr/bin/env python3
"""
Claude Guard — CLI entry point for Cloud Watchdog.

Usage:
    claude-guard             Launch Claude Code with Cloud Watchdog supervision
    claude-guard scan        Manually refresh the infrastructure graph
    claude-guard scan --aws  Scan AWS only
    claude-guard scan --gcp  Scan GCP only
    claude-guard status      Show watchdog status (last scan, resource count, etc.)
    claude-guard login       Log in to your Claude Guard team
    claude-guard logout      Log out and remove stored credentials
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# The directory where Cloud Watchdog stores persistent data.
WATCHDOG_DIR = Path.home() / ".cloud-watchdog"

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# API key resolution — env var first, then Claude Code's keychain credential
# ---------------------------------------------------------------------------

def resolve_api_key() -> str | None:
    """Resolve the Anthropic API key from available sources.

    Checks in order:
    1. ``ANTHROPIC_API_KEY`` environment variable
    2. macOS Keychain — reads Claude Code's stored OAuth token

    Returns the key string, or *None* if nothing was found.
    """
    # 1. Explicit environment variable (always wins).
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key and key.startswith("sk-ant-"):
        return key

    return None


_KNOWN_COMMANDS = ("scan", "status", "login", "logout")

# Default server URL (production).
_DEFAULT_SERVER_URL = "https://api.claudeguard.com"

# Path to the stored credentials / config.
_CONFIG_FILE = WATCHDOG_DIR / "config.json"


def _load_config() -> dict:
    """Load the stored config (server URL, tokens, org info)."""
    if _CONFIG_FILE.exists():
        try:
            return json.loads(_CONFIG_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_config(cfg: dict) -> None:
    """Persist config to disk."""
    WATCHDOG_DIR.mkdir(parents=True, exist_ok=True)
    _CONFIG_FILE.write_text(json.dumps(cfg, indent=2) + "\n")


def main() -> None:
    """Dispatch to the appropriate sub-command."""
    args = sys.argv[1:]

    if not args or args[0] not in _KNOWN_COMMANDS:
        _launch_claude(args)
    elif args[0] == "scan":
        _cmd_scan(args[1:])
    elif args[0] == "status":
        _cmd_status()
    elif args[0] == "login":
        _cmd_login()
    elif args[0] == "logout":
        _cmd_logout()
    else:
        print(f"Unknown command: {args[0]}", file=sys.stderr)
        print(__doc__, file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# claude-guard login / logout
# ---------------------------------------------------------------------------

def _cmd_login() -> None:
    """Interactive login — first-run onboarding or re-login."""
    import getpass

    cfg = _load_config()
    if cfg.get("access_token") and cfg.get("org_name"):
        print(
            f"\033[32mAlready logged in to {cfg['org_name']}.\033[0m",
            file=sys.stderr,
        )
        return

    server_url = cfg.get("server_url") or _DEFAULT_SERVER_URL

    try:
        import requests as req
    except ImportError:
        print(
            "\033[1;31mError:\033[0m 'requests' package is required.\n"
            "  pip install requests",
            file=sys.stderr,
        )
        sys.exit(1)

    while True:
        print("\033[1;31m━━━ CLAUDE GUARD LOGIN ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")

        # Decide: existing account or new registration.
        choice = input("  (1) Log in to existing account\n"
                        "  (2) Register with team invite code\n"
                        "  Choice [1/2]: ").strip()

        if choice == "2":
            invite_code = input("  Team invite code: ").strip()
            email = input("  Email: ").strip()
            password = getpass.getpass("  Password: ")
            display_name = input("  Display name (optional): ").strip()

            resp = req.post(
                f"{server_url}/api/v1/auth/register",
                json={
                    "invite_code": invite_code,
                    "email": email,
                    "password": password,
                    "display_name": display_name or email.split("@")[0],
                },
                timeout=30,
            )
        else:
            email = input("  Email: ").strip()
            password = getpass.getpass("  Password: ")

            resp = req.post(
                f"{server_url}/api/v1/auth/login",
                json={"email": email, "password": password},
                timeout=30,
            )

        if resp.status_code == 200:
            data = resp.json()
            break

        detail = resp.json().get("detail", resp.text)
        print(f"\n\033[1;31mFailed:\033[0m {detail}", file=sys.stderr)
        retry = input("  Try again? [Y/n]: ").strip().lower()
        if retry == "n":
            sys.exit(1)
        print()

    _save_config({
        "server_url": server_url,
        "access_token": data["access_token"],
        "refresh_token": data["refresh_token"],
        "org_name": data["org_name"],
        "org_id": data["org_id"],
    })

    print(f"\n  \033[32m✓ Logged in to {data['org_name']}. You're all set!\033[0m")
    print("\033[1;31m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")


def _cmd_logout() -> None:
    """Remove stored credentials."""
    if _CONFIG_FILE.exists():
        _CONFIG_FILE.unlink()
        print("\033[32mLogged out.\033[0m", file=sys.stderr)
    else:
        print("Not logged in.", file=sys.stderr)


# ---------------------------------------------------------------------------
# Server sync helper
# ---------------------------------------------------------------------------

def _sync_to_server(cfg: dict) -> None:
    """Upload local scan results to the Claude Guard server."""
    from scanner.graph import GraphDB
    db = GraphDB()
    summary = db.get_scan_summary()

    if summary["resource_count"] == 0:
        return

    try:
        import requests as req
    except ImportError:
        return

    # Read all resources and relationships from local SQLite.
    import sqlite3
    conn = sqlite3.connect(db._db_path)
    conn.row_factory = sqlite3.Row

    resources = []
    for row in conn.execute("SELECT * FROM resources"):
        r = dict(row)
        # Parse JSON fields.
        for key in ("metadata", "tags"):
            if r.get(key) and isinstance(r[key], str):
                try:
                    r[key] = json.loads(r[key])
                except (json.JSONDecodeError, TypeError):
                    pass
        resources.append(r)

    relationships = []
    for row in conn.execute("SELECT * FROM relationships"):
        r = dict(row)
        if r.get("metadata") and isinstance(r["metadata"], str):
            try:
                r["metadata"] = json.loads(r["metadata"])
            except (json.JSONDecodeError, TypeError):
                pass
        relationships.append({
            "source_arn": r["source_arn"],
            "target_arn": r["target_arn"],
            "rel_type": r["rel_type"],
            "metadata": r.get("metadata"),
        })
    conn.close()

    server_url = cfg.get("server_url", _DEFAULT_SERVER_URL)
    token = cfg.get("access_token", "")

    try:
        resp = req.post(
            f"{server_url}/api/v1/graph/sync",
            json={"resources": resources, "relationships": relationships},
            headers={"Authorization": f"Bearer {token}"},
            timeout=60,
        )
        if resp.status_code == 200:
            data = resp.json()
            print(
                f"\033[32m  Synced to server: {data['resources_upserted']} resources, "
                f"{data['relationships_upserted']} relationships\033[0m",
                file=sys.stderr,
            )
        else:
            print(
                f"\033[33m  Server sync failed: {resp.status_code}\033[0m",
                file=sys.stderr,
            )
    except Exception as exc:
        print(
            f"\033[33m  Server sync failed: {exc}\033[0m",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# First-run login prompt
# ---------------------------------------------------------------------------

def _ensure_login() -> dict:
    """If not logged in, prompt the user. Returns the config dict."""
    cfg = _load_config()
    if cfg.get("access_token"):
        return cfg

    print(
        "\033[33m  Not logged in to Claude Guard.\033[0m\n"
        "  Run: claude-guard login\n",
        file=sys.stderr,
    )
    return cfg


# ---------------------------------------------------------------------------
# claude-guard (default) — install hooks → launch claude → clean up
# ---------------------------------------------------------------------------

def _launch_claude(extra_args: list[str]) -> None:
    """Install a temporary PreToolUse hook, launch Claude, and clean up."""
    cfg = _load_config()

    # If logged in to server, use server mode (no local API key needed).
    server_url = cfg.get("server_url")
    server_token = cfg.get("access_token")
    use_server = bool(server_url and server_token)

    api_key = None
    if not use_server:
        api_key = resolve_api_key()
        if not api_key:
            # No server login and no API key — run interactive login.
            print(
                "\033[33m  No Cloud Guard credentials found. "
                "Let's get you set up.\033[0m\n",
                file=sys.stderr,
            )
            _cmd_login()
            # Reload config after login.
            cfg = _load_config()
            server_url = cfg.get("server_url")
            server_token = cfg.get("access_token")
            use_server = bool(server_url and server_token)
            if not use_server:
                print(
                    "\033[1;31mError:\033[0m Login did not complete. "
                    "Run claude-guard login to try again.",
                    file=sys.stderr,
                )
                sys.exit(1)

    # Locate the hook script.
    hook_script = Path(__file__).resolve().parent / "watchdog" / "hook.py"
    if not hook_script.exists():
        print(
            f"\033[1;31mError:\033[0m Hook script not found at {hook_script}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Ensure watchdog dir exists.
    WATCHDOG_DIR.mkdir(parents=True, exist_ok=True)

    # Build the hook configuration.
    if use_server:
        # Server mode: pass server URL + token to hook via env vars.
        hook_command = (
            f"GUARD_SERVER_URL={server_url} "
            f"GUARD_TOKEN={server_token} "
            f"python3 {hook_script}"
        )
    else:
        # Local mode: pass API key directly.
        hook_command = f"ANTHROPIC_API_KEY={api_key} python3 {hook_script}"

    hook_config = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                            "timeout": 120,
                            "statusMessage": "Cloud Watchdog analyzing...",
                        }
                    ],
                }
            ]
        }
    }

    # Write the hook config to a temporary file.
    # We use a project-level .claude/settings.local.json so it only affects
    # the current invocation.
    settings_dir = Path.cwd() / ".claude"
    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_file = settings_dir / "settings.local.json"

    # Back up existing settings if present.
    backup_file = None
    if settings_file.exists():
        backup_file = settings_file.with_suffix(".local.json.cg-backup")
        shutil.copy2(settings_file, backup_file)

    # Merge hook config with existing settings (if any).
    existing = {}
    if settings_file.exists():
        try:
            existing = json.loads(settings_file.read_text())
        except (json.JSONDecodeError, OSError):
            existing = {}

    # Preserve existing hooks and add ours.
    existing_hooks = existing.get("hooks", {})
    existing_pre = existing_hooks.get("PreToolUse", [])
    merged_pre = hook_config["hooks"]["PreToolUse"] + existing_pre
    existing_hooks["PreToolUse"] = merged_pre
    existing["hooks"] = existing_hooks

    settings_file.write_text(json.dumps(existing, indent=2) + "\n")

    print(
        "\033[1;31m━━━ CLOUD WATCHDOG ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m",
        file=sys.stderr,
    )
    if use_server:
        org_name = cfg.get("org_name", "your team")
        print(
            f"\033[31m  Connected to {org_name} (server mode)\033[0m",
            file=sys.stderr,
        )
    print(
        "\033[31m  Hook installed. Launching Claude Code...\033[0m",
        file=sys.stderr,
    )
    print(
        "\033[31m  All cloud commands will be supervised.\033[0m",
        file=sys.stderr,
    )
    print(
        "\033[1;31m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m",
        file=sys.stderr,
    )

    # Find the claude binary.
    claude_bin = shutil.which("claude")
    if claude_bin is None:
        print(
            "\033[1;31mError:\033[0m `claude` not found in PATH.\n"
            "Install Claude Code first: https://docs.anthropic.com/en/docs/claude-code",
            file=sys.stderr,
        )
        _restore_settings(settings_file, backup_file)
        sys.exit(1)

    try:
        run_env = dict(os.environ)
        if use_server:
            run_env["GUARD_SERVER_URL"] = server_url
            run_env["GUARD_TOKEN"] = server_token
        # Note: don't inject ANTHROPIC_API_KEY into Claude Code's env —
        # it conflicts with Claude Code's own OAuth login. The hook
        # command already receives the key inline (see hook_command above).
        run_env.pop("ANTHROPIC_API_KEY", None)
        result = subprocess.run(
            [claude_bin] + extra_args,
            env=run_env,
        )
        sys.exit(result.returncode)
    except KeyboardInterrupt:
        pass
    finally:
        _restore_settings(settings_file, backup_file)
        print(
            "\n\033[31m  Cloud Watchdog hook removed. Session ended.\033[0m",
            file=sys.stderr,
        )


def _restore_settings(settings_file: Path, backup_file: Path | None) -> None:
    """Restore the original settings file (or remove our temporary one)."""
    try:
        if backup_file and backup_file.exists():
            shutil.move(str(backup_file), str(settings_file))
        elif settings_file.exists():
            settings_file.unlink()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# claude-guard scan — manual infrastructure scan
# ---------------------------------------------------------------------------

def _cmd_scan(args: list[str]) -> None:
    """Manually refresh the infrastructure graph."""
    from scanner.graph import GraphDB

    db = GraphDB()
    scan_aws_flag = "--aws" in args or not any(f in args for f in ("--aws", "--gcp"))
    scan_gcp_flag = "--gcp" in args or not any(f in args for f in ("--aws", "--gcp"))

    if scan_aws_flag:
        try:
            from scanner.aws import scan_aws
            print("\033[31mScanning AWS infrastructure...\033[0m", file=sys.stderr)
            summary = scan_aws(db)
            print(
                f"\033[31mAWS: {summary['resource_count']} resources, "
                f"{summary['relationship_count']} relationships\033[0m",
                file=sys.stderr,
            )
        except ImportError:
            print(
                "\033[33mboto3 not installed — skipping AWS scan.\033[0m",
                file=sys.stderr,
            )
        except Exception as exc:
            print(f"\033[31mAWS scan failed: {exc}\033[0m", file=sys.stderr)

    if scan_gcp_flag:
        try:
            from scanner.gcp import scan_gcp
            print("\033[31mScanning GCP infrastructure...\033[0m", file=sys.stderr)
            summary = scan_gcp(db)
            print(
                f"\033[31mGCP: {summary['resource_count']} resources, "
                f"{summary['relationship_count']} relationships\033[0m",
                file=sys.stderr,
            )
        except ImportError:
            print(
                "\033[33mgoogle-cloud libraries not installed — skipping GCP scan.\033[0m",
                file=sys.stderr,
            )
        except Exception as exc:
            print(f"\033[31mGCP scan failed: {exc}\033[0m", file=sys.stderr)

    print("\033[32mScan complete.\033[0m", file=sys.stderr)

    # Auto-sync to server if logged in.
    cfg = _load_config()
    if cfg.get("access_token"):
        _sync_to_server(cfg)


# ---------------------------------------------------------------------------
# claude-guard status — show watchdog state
# ---------------------------------------------------------------------------

def _cmd_status() -> None:
    """Show the current state of the watchdog."""
    from scanner.graph import GraphDB

    db = GraphDB()
    summary = db.get_scan_summary()

    resource_count = summary["resource_count"]
    relationship_count = summary["relationship_count"]
    env = summary.get("environment_breakdown", {})
    last_scan = summary.get("last_scan_time")

    staleness = db.staleness_minutes()

    print("\033[1;31m━━━ CLOUD WATCHDOG STATUS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
    print(f"\033[31m  Resources:     {resource_count}\033[0m")
    print(f"\033[31m  Relationships: {relationship_count}\033[0m")
    print(
        f"\033[31m  Environments:  "
        f"{env.get('prod', 0)} prod · "
        f"{env.get('staging', 0)} staging · "
        f"{env.get('dev', 0)} dev · "
        f"{env.get('unknown', 0)} unknown\033[0m"
    )

    if last_scan:
        if staleness >= 0:
            if staleness < 60:
                age = f"{staleness} minutes ago"
            else:
                age = f"{staleness // 60} hours ago"
        else:
            age = "unknown"
        print(f"\033[31m  Last scan:     {last_scan} ({age})\033[0m")
    else:
        print("\033[31m  Last scan:     never\033[0m")

    print(f"\033[31m  Database:      {db.db_path}\033[0m")
    print("\033[1;31m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")


if __name__ == "__main__":
    main()
