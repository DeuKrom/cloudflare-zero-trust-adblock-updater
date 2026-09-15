from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Iterator

from .models import AppState, ChunkState, RuleState


class StateError(RuntimeError):
    pass


def safe_state_path(path: str) -> Path:
    if not path or "\x00" in path or "\n" in path or "\r" in path:
        raise StateError("[ERROR] Некорректный STATE_FILE")
    # Cross-platform traversal check (Windows + POSIX separators).
    normalized = path.replace("\\", "/")
    if ".." in normalized.split("/"):
        raise StateError("[ERROR] STATE_FILE не должен содержать '..'")
    p = Path(path)
    if p.is_absolute() or normalized.startswith("/"):
        # POSIX absolute on Windows is not detected by Path.is_absolute().
        try:
            # /etc/... никогда не внутри CWD на Windows -> запрет.
            if normalized.startswith("/") and os.name == "nt":
                raise ValueError("posix absolute")
            p.resolve().relative_to(Path.cwd().resolve())
        except ValueError as exc:
            raise StateError("[ERROR] STATE_FILE за пределами рабочей директории запрещён") from exc
    if p.suffix.lower() != ".json":
        raise StateError("[ERROR] STATE_FILE должен заканчиваться на .json")
    return p


def _validate_state_dict(data: dict) -> None:
    if not isinstance(data, dict):
        raise StateError("[ERROR] State-файл повреждён: корень не объект")
    chunks = data.get("chunks", [])
    if not isinstance(chunks, list):
        raise StateError("[ERROR] State-файл повреждён: chunks не список")
    for c in chunks:
        if not isinstance(c, dict):
            raise StateError("[ERROR] State-файл повреждён: chunk не объект")
        for f in ("index", "name", "cloudflare_list_id", "item_count", "chunk_hash"):
            if f not in c:
                raise StateError(f"[ERROR] State-файл повреждён: chunk без поля {f}")
        if not isinstance(c["index"], int) or not isinstance(c["item_count"], int):
            raise StateError("[ERROR] State-файл повреждён: неверные типы chunk")
        if not isinstance(c["name"], str) or not isinstance(c["cloudflare_list_id"], str):
            raise StateError("[ERROR] State-файл повреждён: неверные типы chunk")
    rule = data.get("rule")
    if rule is not None:
        if not isinstance(rule, dict):
            raise StateError("[ERROR] State-файл повреждён: rule не объект")
        for f in ("name", "cloudflare_rule_id", "precedence"):
            if f not in rule:
                raise StateError(f"[ERROR] State-файл повреждён: rule без поля {f}")


def read_state(path: str) -> AppState | None:
    p = safe_state_path(path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise StateError("[ERROR] State-файл повреждён или не является корректным JSON") from exc
    except OSError as exc:
        raise StateError(f"[ERROR] Не удалось прочитать state-файл: {exc}") from exc

    try:
        _validate_state_dict(data)
        chunks = [ChunkState(**c) for c in data.get("chunks", [])]
        rule_raw = data.get("rule")
        rule = RuleState(**rule_raw) if rule_raw else None
        return AppState(
            managed_by=str(data.get("managed_by", "cf-zt-oisd-sync")),
            list_prefix=str(data.get("list_prefix", "oisd-small-auto")),
            rule_name=str(data.get("rule_name", "OISD Small Auto Block")),
            source_url=str(data.get("source_url", "https://small.oisd.nl")),
            chunk_size=int(data.get("chunk_size", 1000)),
            last_sync_at=data.get("last_sync_at"),
            source_hash=data.get("source_hash"),
            raw_source_hash=data.get("raw_source_hash"),
            domain_count=int(data.get("domain_count", 0)),
            chunks=chunks,
            rule=rule,
        )
    except (TypeError, ValueError) as exc:
        raise StateError(f"[ERROR] State-файл повреждён: {exc}") from exc


def write_state(path: str, state: AppState) -> None:
    p = safe_state_path(path)
    if p.parent and str(p.parent) not in ("", "."):
        p.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(asdict(state), ensure_ascii=False, indent=2)
    tmp = p.with_name(p.name + f".tmp-{os.getpid()}")
    tmp.write_text(payload, encoding="utf-8")
    try:
        with open(tmp, "rb") as f:
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
    except OSError:
        pass
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    # Backup previous version (best effort).
    try:
        if p.exists():
            bak = p.with_name(p.name + ".bak")
            try:
                bak.write_bytes(p.read_bytes())
            except OSError:
                pass
    except OSError:
        pass
    tmp.replace(p)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def delete_state(path: str) -> bool:
    p = safe_state_path(path)
    if not p.exists():
        return False
    p.unlink()
    # Cleanup backup (best effort, ignore errors).
    try:
        bak = p.with_name(p.name + ".bak")
        if bak.exists():
            bak.unlink()
    except OSError:
        pass
    return True


@contextmanager
def state_lock(path: str, timeout: float = 30.0, stale_after: float = 900.0) -> Iterator[None]:
    """Cross-platform lock via exclusive .lock file. Stale locks are broken."""
    p = safe_state_path(path)
    lock_path = p.with_name(p.name + ".lock")
    start = time.monotonic()
    acquired = False
    while not acquired:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(fd, f"{os.getpid()}\n{time.time()}".encode("utf-8"))
            finally:
                os.close(fd)
            acquired = True
        except FileExistsError:
            try:
                age = time.time() - lock_path.stat().st_mtime
            except OSError:
                age = 0
            if age > stale_after:
                try:
                    lock_path.unlink()
                except OSError:
                    pass
            elif time.monotonic() - start > timeout:
                raise StateError(
                    "[ERROR] State-файл заблокирован другим процессом "
                    f"({lock_path.name}). Дождитесь конца или удалите lock при зависшем процессе."
                )
            else:
                time.sleep(0.2)
    try:
        yield
    finally:
        try:
            lock_path.unlink()
        except OSError:
            pass
