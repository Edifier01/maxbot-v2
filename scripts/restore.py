from __future__ import annotations

import argparse
import sqlite3
import zipfile
from pathlib import Path, PurePosixPath


def restore_backup(archive_path: Path, target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    if any(target_dir.iterdir()):
        raise ValueError("restore_target_must_be_empty")
    with zipfile.ZipFile(archive_path) as archive:
        files = {}
        for info in archive.infolist():
            path = PurePosixPath(info.filename)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("unsafe_backup_path")
            if info.is_dir():
                continue
            if path.name == "database.sqlite3":
                relative = Path("maxbot.sqlite3")
            elif path.parts[:1] == ("sessions",) and path.suffix == ".enc":
                relative = Path(*path.parts)
            else:
                continue
            output = target_dir / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(archive.read(info))
            files[relative] = output
    db = files.get(Path("maxbot.sqlite3"))
    if db is None:
        raise ValueError("database_missing_from_backup")
    connection = sqlite3.connect(db)
    try:
        result = connection.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        connection.close()
    if result != "ok":
        raise ValueError("restored_database_integrity_check_failed")


def main() -> None:
    parser = argparse.ArgumentParser(description="Restore into an empty data directory")
    parser.add_argument("archive", type=Path)
    parser.add_argument("target", type=Path)
    args = parser.parse_args()
    restore_backup(args.archive, args.target)


if __name__ == "__main__":
    main()
