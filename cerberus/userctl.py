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
    args = parser.parse_args()
    if args.command == "create":
        if args.password_file:
            password = Path(args.password_file).read_text(encoding="utf-8").rstrip("\r\n")
        else:
            password = getpass.getpass("Password (12+ characters): ")
            if password != getpass.getpass("Confirm password: "):
                raise SystemExit("passwords do not match")
        user = local_auth.create_owner(args.username, password)
        print(f"Created local owner: {user['username']}")


if __name__ == "__main__":
    main()
