"""Command-line interface.

    ciphervault init                 create a user and master password
    ciphervault add github           store a secret (prompts for values)
    ciphervault get github [--show]  print an entry (secret hidden unless --show)
    ciphervault list                 list entry names
    ciphervault delete github
    ciphervault passwd               change master password
    ciphervault generate [-n 24]     print a random password
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from . import crypto
from .db import Database
from .vault import AuthError, Entry, EntryNotFound, Vault, VaultLocked

DEFAULT_DB = "sqlite:///ciphervault.db"


def _prompt_new_password() -> str:
    pw = getpass.getpass("New master password (min 12 chars): ")
    if pw != getpass.getpass("Confirm master password: "):
        sys.exit("Passwords do not match.")
    return pw


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ciphervault", description="Encrypted secret vault")
    p.add_argument("--db", default=os.environ.get("CIPHERVAULT_DB", DEFAULT_DB))
    p.add_argument("-u", "--user", default=os.environ.get("CIPHERVAULT_USER", getpass.getuser()))
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    a = sub.add_parser("add"); a.add_argument("name"); a.add_argument("--generate", action="store_true")
    a.add_argument("--overwrite", action="store_true")
    g = sub.add_parser("get"); g.add_argument("name"); g.add_argument("--show", action="store_true")
    sub.add_parser("list")
    d = sub.add_parser("delete"); d.add_argument("name")
    sub.add_parser("passwd")
    gen = sub.add_parser("generate"); gen.add_argument("-n", "--length", type=int, default=20)
    gen.add_argument("--no-symbols", action="store_true")
    args = p.parse_args(argv)

    if args.cmd == "generate":
        print(crypto.generate_password(args.length, not args.no_symbols))
        return 0

    db = Database.connect(args.db)
    db.init_schema()
    try:
        if args.cmd == "init":
            Vault.register(db, args.user, _prompt_new_password())
            print(f"Vault created for {args.user}.")
            return 0

        vault = Vault.unlock(db, args.user, getpass.getpass(f"Master password for {args.user}: "))

        if args.cmd == "add":
            secret = crypto.generate_password() if args.generate else getpass.getpass("Secret: ")
            vault.add(
                Entry(
                    name=args.name,
                    secret=secret,
                    username=input("Username (optional): "),
                    url=input("URL (optional): "),
                    notes=input("Notes (optional): "),
                ),
                overwrite=args.overwrite,
            )
            print(f"Saved {args.name}." + (f" Generated secret: {secret}" if args.generate else ""))
        elif args.cmd == "get":
            e = vault.get(args.name)
            print(f"name:     {e.name}\nusername: {e.username}\nurl:      {e.url}\nnotes:    {e.notes}")
            print(f"secret:   {e.secret if args.show else '******** (use --show)'}")
        elif args.cmd == "list":
            names = vault.list_names()
            print("\n".join(names) if names else "(vault is empty)")
        elif args.cmd == "delete":
            vault.delete(args.name)
            print(f"Deleted {args.name}.")
        elif args.cmd == "passwd":
            old = getpass.getpass("Current master password: ")
            vault.change_master_password(old, _prompt_new_password())
            print("Master password changed; all entries re-encrypted.")
        vault.lock()
        return 0
    except (AuthError, VaultLocked, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except EntryNotFound as exc:
        print(f"Error: no entry named {exc.args[0]!r}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
