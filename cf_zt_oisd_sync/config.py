from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from .oisd import validate_oisd_url


class ConfigError(RuntimeError):
    pass


ACCOUNT_ID_RE = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
LIST_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")


@dataclass
class Config:
    cloudflare_api_token: str
    cloudflare_account_id: str
    oisd_source_url: str = "https://small.oisd.nl"
    list_prefix: str = "oisd-small-auto"
    rule_name: str = "OISD Small Auto Block"
    chunk_size: int = 1000
    list_workers: int = 4
    rule_precedence: int = 5000
    state_file: str = ".cf-zt-oisd-state.json"
    dry_run: bool = False
    language: str = "en"
    min_domains: int = 5000
    max_drop_ratio: float = 0.5
    max_lists: int = 500
    allowlist: frozenset[str] = frozenset()
    force: bool = False


def _bool_env(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        v = int(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"[ERROR] {name} должен быть целым числом (получено {raw!r})") from exc
    if not (lo <= v <= hi):
        raise ConfigError(f"[ERROR] {name} должен быть в диапазоне {lo}..{hi} (получено {v})")
    return v


def _float_env(name: str, default: float, lo: float, hi: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        v = float(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"[ERROR] {name} должен быть числом (получено {raw!r})") from exc
    if not (lo <= v <= hi):
        raise ConfigError(f"[ERROR] {name} должен быть в диапазоне {lo}..{hi} (получено {v})")
    return v


def _clean_single_line(name: str, value: str, max_len: int, allow_empty: bool = False) -> str:
    v = value.strip()
    if not v and not allow_empty:
        raise ConfigError(f"[ERROR] {name} пуст")
    if "\n" in value or "\r" in value or "\x00" in value:
        raise ConfigError(f"[ERROR] {name} содержит перенос строки/NUL — запрещено")
    if len(v) > max_len:
        raise ConfigError(f"[ERROR] {name} длиннее {max_len} символов")
    return v


def _parse_allowlist(raw: str | None) -> frozenset[str]:
    if not raw:
        return frozenset()
    parts = [p.strip().lower().strip(".") for p in raw.replace("\n", ",").replace(";", ",").split(",")]
    return frozenset(p for p in parts if p)


def load_config(require_cloudflare: bool = True) -> Config:
    load_dotenv()
    token = os.getenv("CLOUDFLARE_API_TOKEN", "").strip()
    account = os.getenv("CLOUDFLARE_ACCOUNT_ID", "").strip()
    if require_cloudflare and not token:
        raise ConfigError("[ERROR] Не задан CLOUDFLARE_API_TOKEN")
    if require_cloudflare and not account:
        raise ConfigError("[ERROR] Не задан CLOUDFLARE_ACCOUNT_ID")
    if token and ("\n" in token or "\r" in token or " " in token or len(token) < 20):
        raise ConfigError("[ERROR] CLOUDFLARE_API_TOKEN выглядит некорректно")
    if account and not ACCOUNT_ID_RE.match(account):
        raise ConfigError("[ERROR] CLOUDFLARE_ACCOUNT_ID должен быть 32 hex-символами")

    chunk_size = _int_env("CHUNK_SIZE", 1000, 1, 10000)
    list_workers = _int_env("LIST_WORKERS", 8, 1, 16)
    rule_precedence = _int_env("RULE_PRECEDENCE", 5000, 1, 65000)
    min_domains = _int_env("MIN_DOMAINS", 5000, 1, 1_000_000)
    max_lists = _int_env("MAX_LISTS", 500, 1, 5000)
    max_drop_ratio = _float_env("MAX_DROP_RATIO", 0.5, 0.0, 1.0)

    raw_url = os.getenv("OISD_SOURCE_URL", "https://small.oisd.nl").strip()
    try:
        oisd_url = validate_oisd_url(raw_url)
    except Exception as exc:
        raise ConfigError(str(exc)) from exc

    raw_prefix = os.getenv("LIST_PREFIX", "oisd-small-auto")
    prefix = _clean_single_line("LIST_PREFIX", raw_prefix, 64)
    if not PREFIX_RE.match(prefix):
        raise ConfigError("[ERROR] LIST_PREFIX: только латиница/цифры/_/-, начинается с буквы/цифры")

    raw_rule = os.getenv("RULE_NAME", "OISD Small Auto Block")
    rule_name = _clean_single_line("RULE_NAME", raw_rule, 128)

    raw_state = os.getenv("STATE_FILE", ".cf-zt-oisd-state.json")
    state_file = _clean_single_line("STATE_FILE", raw_state, 512)
    normalized_state = state_file.replace("\\", "/")
    if ".." in normalized_state.split("/"):
        raise ConfigError("[ERROR] STATE_FILE не должен содержать '..'")
    if "/" in state_file or "\\" in state_file:
        # Allow relative subpaths but forbid traversal; absolute outside CWD forbidden.
        p = Path(state_file)
        if p.is_absolute() or normalized_state.startswith("/"):
            try:
                if normalized_state.startswith("/") and os.name == "nt":
                    raise ValueError("posix absolute")
                p.resolve().relative_to(Path.cwd().resolve())
            except ValueError as exc:
                raise ConfigError("[ERROR] STATE_FILE за пределами рабочей директории запрещён") from exc
    if not state_file.endswith(".json"):
        raise ConfigError("[ERROR] STATE_FILE должен заканчиваться на .json")

    lang = os.getenv("LANGUAGE", "en").strip().lower()
    if lang not in {"en", "ru"}:
        raise ConfigError("[ERROR] LANGUAGE должен быть en или ru")

    allowlist = _parse_allowlist(os.getenv("ALLOWLIST", ""))
    allowlist_file = os.getenv("ALLOWLIST_FILE", "").strip()
    if allowlist_file:
        if "\n" in allowlist_file or "\r" in allowlist_file or "\x00" in allowlist_file:
            raise ConfigError("[ERROR] ALLOWLIST_FILE содержит перенос строки")
        af = Path(allowlist_file)
        normalized_af = allowlist_file.replace("\\", "/")
        if af.is_absolute() or normalized_af.startswith("/") or ".." in normalized_af.split("/"):
            raise ConfigError("[ERROR] ALLOWLIST_FILE: только относительный путь без '..'")
        if af.exists():
            try:
                extra = _parse_allowlist(af.read_text(encoding="utf-8"))
            except OSError as exc:
                raise ConfigError(f"[ERROR] Не удалось прочитать ALLOWLIST_FILE: {exc}") from exc
            allowlist = allowlist | extra

    return Config(
        cloudflare_api_token=token,
        cloudflare_account_id=account,
        oisd_source_url=oisd_url,
        list_prefix=prefix,
        rule_name=rule_name,
        chunk_size=chunk_size,
        list_workers=list_workers,
        rule_precedence=rule_precedence,
        state_file=state_file,
        dry_run=_bool_env("DRY_RUN", False),
        language=lang,
        min_domains=min_domains,
        max_drop_ratio=max_drop_ratio,
        max_lists=max_lists,
        allowlist=allowlist,
        force=_bool_env("FORCE", False),
    )


ENV_KEY_ORDER = [
    "CLOUDFLARE_ACCOUNT_ID",
    "CLOUDFLARE_API_TOKEN",
    "OISD_SOURCE_URL",
    "LIST_PREFIX",
    "RULE_NAME",
    "CHUNK_SIZE",
    "LIST_WORKERS",
    "RULE_PRECEDENCE",
    "STATE_FILE",
    "DRY_RUN",
    "LANGUAGE",
    "MIN_DOMAINS",
    "MAX_DROP_RATIO",
    "MAX_LISTS",
    "ALLOWLIST",
]


def sanitize_env_values(values: dict[str, str]) -> dict[str, str]:
    """Validate .env values before writing (anti-injection)."""
    out: dict[str, str] = {}
    for k, v in values.items():
        if not isinstance(v, str):
            v = str(v)
        if "\n" in v or "\r" in v or "\x00" in v:
            raise ConfigError(f"[ERROR] Значение {k} содержит перенос строки — запрещено")
        vv = v.strip()
        if k == "CLOUDFLARE_ACCOUNT_ID" and vv and not ACCOUNT_ID_RE.match(vv):
            raise ConfigError("[ERROR] CLOUDFLARE_ACCOUNT_ID должен быть 32 hex-символами")
        if k == "CLOUDFLARE_API_TOKEN" and vv and (len(vv) < 20 or " " in vv):
            raise ConfigError("[ERROR] CLOUDFLARE_API_TOKEN выглядит некорректно")
        if k == "LIST_PREFIX" and vv and not PREFIX_RE.match(vv):
            raise ConfigError("[ERROR] LIST_PREFIX: только латиница/цифры/_/-")
        if k in {"CHUNK_SIZE", "LIST_WORKERS", "RULE_PRECEDENCE", "MIN_DOMAINS", "MAX_LISTS"} and vv:
            if not vv.lstrip("-").isdigit():
                raise ConfigError(f"[ERROR] {k} должен быть целым числом")
        out[k] = vv
    return out


def write_env_file(path: str | Path, values: dict[str, str]) -> None:
    """Atomic .env write with 0600 permissions."""
    import os as _os

    clean = sanitize_env_values(values)
    ordered = [(k, clean[k]) for k in ENV_KEY_ORDER if k in clean]
    ordered += sorted((k, v) for k, v in clean.items() if k not in ENV_KEY_ORDER)
    text = "\n".join(f"{k}={v}" for k, v in ordered) + "\n"
    p = Path(path)
    tmp = p.with_name(p.name + f".tmp-{_os.getpid()}")
    tmp.write_text(text, encoding="utf-8")
    try:
        _os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(p)
    try:
        _os.chmod(p, 0o600)
    except OSError:
        pass
