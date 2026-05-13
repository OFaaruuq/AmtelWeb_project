from __future__ import annotations

import argparse
import getpass
import secrets
import string
from pathlib import Path

from werkzeug.security import generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"


def generate_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def upsert_env_value(content: str, key: str, value: str) -> str:
    replacement = f"{key}={value}"
    lines = content.splitlines()
    for index, line in enumerate(lines):
        if line.startswith(f"{key}="):
            lines[index] = replacement
            return "\n".join(lines) + "\n"
    lines.append(replacement)
    return "\n".join(lines) + "\n"


def update_env_file(username: str | None, password_hash: str) -> None:
    content = ENV_PATH.read_text(encoding="utf-8") if ENV_PATH.exists() else ""
    if username:
        content = upsert_env_value(content, "ADMIN_USERNAME", username)
    content = upsert_env_value(content, "ADMIN_PASSWORD_HASH", password_hash)
    content = upsert_env_value(content, "ADMIN_PASSWORD", "")
    ENV_PATH.write_text(content, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate or reset the AMTEL admin password.")
    parser.add_argument("--username", help="Admin username to write to .env when using --write-env.")
    parser.add_argument("--password", help="Password to hash. If omitted, a secure password is generated.")
    parser.add_argument("--prompt", action="store_true", help="Prompt for the password instead of generating one.")
    parser.add_argument("--length", type=int, default=24, help="Generated password length. Default: 24.")
    parser.add_argument("--write-env", action="store_true", help="Update Admin_Application/.env with ADMIN_PASSWORD_HASH.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.prompt and args.password:
        raise SystemExit("Use either --prompt or --password, not both.")

    if args.prompt:
        password = getpass.getpass("New admin password: ")
        confirm = getpass.getpass("Confirm admin password: ")
        if password != confirm:
            raise SystemExit("Passwords do not match.")
        if not password:
            raise SystemExit("Password cannot be empty.")
    else:
        password = args.password or generate_password(args.length)

    password_hash = generate_password_hash(password)

    if args.write_env:
        update_env_file(args.username, password_hash)
        print(f"Updated {ENV_PATH}")

    print("ADMIN_PASSWORD_HASH:")
    print(password_hash)
    if not args.password and not args.prompt:
        print("\nGenerated admin password:")
        print(password)
    print("\nRestart the admin service after updating .env.")


if __name__ == "__main__":
    main()
