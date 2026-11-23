"""Local operator commands; passwords are read without terminal echo."""

import argparse
import getpass
import json
import time
from uuid import uuid4

from .core import security as auth
from .core import storage as db


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["create-admin", "retention"])
    parser.add_argument("--email")
    args = parser.parse_args()
    if args.command == "retention":
        print(json.dumps({"deleted_jobs": db.purge_expired()}))
        return
    if not args.email or "@" not in args.email:
        parser.error("--email is required")
    password = getpass.getpass("New administrator password (minimum 12 characters): ")
    if len(password) < 12 or password != getpass.getpass("Confirm password: "):
        parser.error("Password is short or confirmation differs")
    with db.transaction() as conn:
        conn.execute(
            db.users.insert().values(
                id=str(uuid4()),
                email=args.email.lower(),
                password_hash=auth.password_hash.hash(password),
                role="admin",
                settings=json.dumps(auth.DEFAULT_SETTINGS),
                created_at=time.time(),
            )
        )
    print("Administrator created. No credentials were printed.")


if __name__ == "__main__":
    main()
