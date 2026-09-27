from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path

from .crypto import SecretBox


class SessionSnapshotUnavailable(RuntimeError):
    """The live PyMax database could not be read as a complete SQLite snapshot."""


class SessionDeletionError(RuntimeError):
    """One or more files belonging to the account could not be removed."""


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

    def has_saved_session_token(self) -> bool:
        """Return whether any token exists in this encrypted generation."""
        if not self.encrypted_path.exists():
            return False
        try:
            raw = self.box.decrypt_bytes(self.encrypted_path.read_bytes())
            database = sqlite3.connect(":memory:")
            try:
                database.deserialize(raw)
                tables = {
                    row[0]
                    for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
                if "sessions" not in tables:
                    return False
                return database.execute(
                    "SELECT 1 FROM sessions WHERE token IS NOT NULL AND token<>'' LIMIT 1"
                ).fetchone() is not None
            finally:
                database.close()
        except Exception as exc:
            raise SessionSnapshotUnavailable("session_snapshot_unavailable") from exc

    def has_saved_session_token_any_generation(self) -> bool:
        """Conservatively inspect all encrypted generations before legacy cleanup."""
        pattern = re.compile(rf"account-{self.account_id}(?:-generation-[0-9]+)?\.session\.(?:enc|tmp)\Z")
        if not self.durable_dir.exists():
            return False
        try:
            paths = [path for path in self.durable_dir.iterdir() if pattern.fullmatch(path.name)]
            for path in paths:
                if path.name.endswith(".tmp"):
                    raise SessionSnapshotUnavailable("session_snapshot_unavailable")
                raw = self.box.decrypt_bytes(path.read_bytes())
                database = sqlite3.connect(":memory:")
                try:
                    database.deserialize(raw)
                    tables = {row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    if "sessions" not in tables:
                        continue
                    if database.execute(
                        "SELECT 1 FROM sessions WHERE token IS NOT NULL AND token<>'' LIMIT 1"
                    ).fetchone() is not None:
                        return True
                finally:
                    database.close()
            return False
        except SessionSnapshotUnavailable:
            raise
        except Exception as exc:
            raise SessionSnapshotUnavailable("session_snapshot_unavailable") from exc

    def delete_all_generations(self) -> None:
        """Remove only durable and temporary session files for this account ID."""
        encrypted_name = re.compile(
            rf"account-{self.account_id}(?:-generation-[0-9]+)?\.session\.(?:enc|tmp)\Z"
        )
        runtime_name = re.compile(rf"account-{self.account_id}(?:-generation-[0-9]+)?\Z")
        errors: list[OSError] = []

        if self.durable_dir.exists():
            for path in self.durable_dir.iterdir():
                if encrypted_name.fullmatch(path.name):
                    try:
                        path.unlink()
                    except OSError as exc:
                        errors.append(exc)

        if self.runtime_dir.exists():
            for directory in self.runtime_dir.iterdir():
                if not runtime_name.fullmatch(directory.name):
                    continue
                if directory.is_symlink():
                    try:
                        directory.unlink()
                    except OSError as exc:
                        errors.append(exc)
                    continue
                if not directory.is_dir():
                    continue
                for path in directory.iterdir():
                    try:
                        if path.is_dir() and not path.is_symlink():
                            raise OSError("unexpected_nested_session_directory")
                        path.unlink()
                    except OSError as exc:
                        errors.append(exc)
                try:
                    directory.rmdir()
                except OSError as exc:
                    errors.append(exc)

        if errors:
            raise SessionDeletionError("session_file_cleanup_failed") from errors[0]

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
