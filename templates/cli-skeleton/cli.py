#!/usr/bin/env python3
"""cli.py — the deliverable: a stable, headless CLI.

Runs the reversed client from the terminal. Clear exit codes (0 = pass,
non-zero = fail with a message), JSON or plain output, session reused from
disk so login isn't repeated. Add one subcommand per action.

Examples:
    python cli.py login --username u --password p
    python cli.py profile --json
"""
from __future__ import annotations

import argparse
import json
import sys

from client import Client


def _print(data, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(data)


def cmd_login(c: Client, args) -> int:
    c.login(args.username, args.password)
    print("login ok; session saved")
    return 0


def cmd_profile(c: Client, args) -> int:
    if not c.load_session():
        print("no session — run `login` first", file=sys.stderr)
        return 2
    _print(c.get_profile(), args.json)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Reversed API client CLI")
    p.add_argument("--json", action="store_true", help="JSON output")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("login", help="authenticate and persist the session")
    sp.add_argument("--username", required=True)
    sp.add_argument("--password", required=True)
    sp.set_defaults(func=cmd_login)

    sp = sub.add_parser("profile", help="read the account profile")
    sp.set_defaults(func=cmd_profile)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    client = Client()
    try:
        return args.func(client, args)
    except Exception as e:                      # fail loud, non-zero exit
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
