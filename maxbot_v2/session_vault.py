from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from .crypto import SecretBox


class SessionSnapshotUnavailable(RuntimeError):
    """The live PyMax database could not be read as a complete SQLite snapshot."""


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

    def snapshot(self) -> bool:
        """Atomically save a consistent encrypted snapshot when a MAX token exists.

        SQLite's backup API includes committed WAL pages. The source database remains
        open and unchanged so PyMax can continue using it after authentication.
        Empty or tokenless databases never replace an existing saved generation.
        """
        if not self.work_path.exists():
            return False
        source = None
        snapshot = None
        try:
            source = sqlite3.connect(self.work_path)
            snapshot = sqlite3.connect(":memory:")
            source.backup(snapshot)
            tables = {row[0] for row in snapshot.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "sessions" not in tables:
                return False
            row = snapshot.execute("SELECT 1 FROM sessions WHERE token IS NOT NULL AND token<>'' LIMIT 1").fetchone()
            if row is None:
                return False
            raw = snapshot.serialize()
        except sqlite3.DatabaseError as exc:
            raise SessionSnapshotUnavailable("session_snapshot_unavailable") from exc
        finally:
            if snapshot is not None:
                snapshot.close()
            if source is not None:
                source.close()

        self.durable_dir.mkdir(parents=True, exist_ok=True)
        encrypted = self.box.encrypt_bytes(raw)
        temp_path = self.encrypted_path.with_suffix(".tmp")
        try:
            with temp_path.open("wb") as handle:
                handle.write(encrypted)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(temp_path, 0o600)
            except OSError:
                pass
            os.replace(temp_path, self.encrypted_path)
        finally:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
        return True

    def seal(self) -> None:
        if not self.work_path.exists():
            return
        try:
            self.snapshot()
        finally:
            self.discard_working_copy()

    def discard_working_copy(self) -> None:
        """Remove plaintext after client close without replacing a durable snapshot."""
        if not self.work_dir.exists():
            return
        for path in self.work_dir.iterdir():
            if path.is_file():
                try:
                    path.unlink()
                except OSError:
                    pass
        try:
            self.work_dir.rmdir()
        except OSError:
            pass
