from getpass import getpass
import bcrypt


def main() -> None:
    first = getpass("New owner password: ")
    second = getpass("Repeat password: ")
    if first != second:
        raise SystemExit("Passwords do not match")
    if len(first) < 12:
        raise SystemExit("Password must be at least 12 characters")
    if len(first.encode("utf-8")) > 72:
        raise SystemExit("Password must be no more than 72 UTF-8 bytes for bcrypt")
    print("OWNER_PASSWORD_HASH=" + bcrypt.hashpw(first.encode(), bcrypt.gensalt(rounds=12)).decode())


if __name__ == "__main__":
    main()
