from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from . import local_auth


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage the local Cerberus owner")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create", help="create the first local owner")
    create.add_argument("--username", required=True)
    create.add_argument("--password-file")
    reset = sub.add_parser(
        "reset-password", help="reset a local owner's password and revoke sessions")
    reset.add_argument("--username", required=True)
    reset.add_argument("--password-file")
    args = parser.parse_args()
    if args.password_file:
        password = Path(args.password_file).read_text(encoding="utf-8").rstrip("\r\n")
    else:
        password = getpass.getpass("Password (12+ characters): ")
        if password != getpass.getpass("Confirm password: "):
            raise SystemExit("passwords do not match")
    if args.command == "create":
        user = local_auth.create_owner(args.username, password)
        print(f"Created local owner: {user['username']}")
    elif args.command == "reset-password":
        local_auth.reset_password(args.username, password)
        print(f"Reset password and revoked sessions for: {args.username}")


if __name__ == "__main__":
    main()
