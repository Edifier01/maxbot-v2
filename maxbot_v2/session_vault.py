from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from .crypto import SecretBox


class EncryptedSessionFile:
    """Encrypted durable snapshot with a transient working copy on tmpfs."""
    def __init__(self, account_id: int, *, generation: int = 0, durable_dir: str | Path, runtime_dir: str | Path, box: SecretBox | None = None):
        self.account_id = int(account_id)
        self.generation = max(0, int(generation))
        self.durable_dir = Path(durable_dir)
        self.runtime_dir = Path(runtime_dir)
        self.box = box or SecretBox()
        suffix = f"-generation-{self.generation}" if self.generation else ""
        self.encrypted_path = self.durable_dir / f"account-{self.account_id}{suffix}.session.enc"
        self.work_dir = self.runtime_dir / f"account-{self.account_id}{suffix}"
        self.work_path = self.work_dir / "session.sqlite3"

    def open(self) -> tuple[str, str]:
        self.durable_dir.mkdir(parents=True, exist_ok=True)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        if self.encrypted_path.exists():
            self.work_path.write_bytes(self.box.decrypt_bytes(self.encrypted_path.read_bytes()))
            try:
                os.chmod(self.work_path, 0o600)
            except OSError:
                pass
        return str(self.work_dir), self.work_path.name

    def seal(self) -> None:
        if not self.work_path.exists():
            return
        try:
            connection = sqlite3.connect(self.work_path)
            try:
                connection.execute("PRAGMA wal_checkpoint(FULL)")
            finally:
                connection.close()
        except sqlite3.DatabaseError:
            pass
        encrypted = self.box.encrypt_bytes(self.work_path.read_bytes())
        temp_path = self.encrypted_path.with_suffix(".tmp")
        temp_path.write_bytes(encrypted)
        try:
            os.chmod(temp_path, 0o600)
        except OSError:
            pass
        temp_path.replace(self.encrypted_path)
        for path in self.work_dir.glob("*"):
            try:
                path.unlink()
            except OSError:
                pass
        try:
            self.work_dir.rmdir()
        except OSError:
            pass

    def discard_working_copy(self) -> None:
        """Remove plaintext after a failed client construction without replacing the durable snapshot."""
        if not self.work_dir.exists():
            return
        for path in self.work_dir.iterdir():
            if path.is_file():
                path.unlink()
        self.work_dir.rmdir()
