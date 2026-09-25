from __future__ import annotations

import argparse
import sqlite3
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def create_backup(database: Path, data_dir: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_db = destination.with_suffix(".sqlite3.tmp")
    source = sqlite3.connect(database)
    target = sqlite3.connect(temp_db)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(temp_db, "database.sqlite3")
        session_dir = data_dir / "sessions"
        if session_dir.exists():
            for path in session_dir.rglob("*"):
                if path.is_file() and path.suffix == ".enc":
                    archive.write(path, path.relative_to(data_dir).as_posix())
        archive.writestr("backup-created-utc.txt", datetime.now(timezone.utc).isoformat())
    temp_db.unlink(missing_ok=True)
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description="Back up the SQLite database and encrypted MAX sessions")
    parser.add_argument("destination", type=Path)
    parser.add_argument("--database", type=Path, default=Path("/data/maxbot.sqlite3"))
    parser.add_argument("--data-dir", type=Path, default=Path("/data"))
    args = parser.parse_args()
    print(create_backup(args.database, args.data_dir, args.destination))


if __name__ == "__main__":
    main()
