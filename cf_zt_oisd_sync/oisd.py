from __future__ import annotations

import hashlib
from urllib.parse import urlparse

import httpx

from .normalize import normalize_domains

DEFAULT_MAX_BYTES = 30 * 1024 * 1024


class OISDError(RuntimeError):
    pass


def validate_oisd_url(url: str) -> str:
    """Validate OISD source URL. Only https without credentials is allowed."""
    u = (url or "").strip()
    if not u:
        raise OISDError("[ERROR] OISD URL пуст")
    try:
        p = urlparse(u)
    except Exception as exc:
        raise OISDError(f"[ERROR] Некорректный OISD URL: {exc}") from exc
    if p.scheme.lower() != "https":
        raise OISDError("[ERROR] OISD URL должен начинаться с https:// (http запрещён)")
    if not p.hostname:
        raise OISDError("[ERROR] OISD URL без хоста")
    if p.username or p.password:
        raise OISDError("[ERROR] OISD URL не должен содержать credentials")
    if "\n" in u or "\r" in u or " " in u:
        raise OISDError("[ERROR] OISD URL содержит пробелы/переносы строк")
    return u


def fetch_oisd_raw(
    url: str,
    timeout: float = 30.0,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_redirects: int = 5,
    retries: int = 2,
) -> str:
    url = validate_oisd_url(url)
    last_err: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with httpx.Client(
                timeout=timeout,
                follow_redirects=True,
                max_redirects=max_redirects,
                headers={"User-Agent": "cf-zt-oisd-sync/0.1.0"},
            ) as client:
                with client.stream("GET", url) as r:
                    # Block downgrade redirects to http and private networks.
                    final_url = str(r.url)
                    if not final_url.lower().startswith("https://"):
                        raise OISDError(f"[ERROR] OISD redirect to non-https blocked: {final_url!r}")
                    # Allow redirects already limited by max_redirects; verify each hop was https.
                    history = getattr(r, "history", []) or []
                    for h in history:
                        hu = str(getattr(h, "url", ""))
                        if hu and not hu.lower().startswith("https://"):
                            raise OISDError(f"[ERROR] OISD redirect hop to non-https blocked: {hu!r}")
                    if r.status_code != 200:
                        raise OISDError(f"[ERROR] OISD вернул HTTP {r.status_code}")
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in r.iter_bytes(chunk_size=65536):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > max_bytes:
                            raise OISDError(
                                f"[ERROR] OISD ответ превышает лимит {max_bytes} байт — abort"
                            )
                        chunks.append(chunk)
                    body = b"".join(chunks).decode("utf-8", errors="strict").strip()
                    if not body:
                        raise OISDError("[ERROR] OISD вернул пустой список")
                    return body
        except OISDError:
            raise
        except (httpx.HTTPError, UnicodeDecodeError) as exc:
            last_err = exc
            if attempt >= retries:
                raise OISDError(f"[ERROR] Не удалось скачать OISD: {exc}") from exc
            continue
    raise OISDError(f"[ERROR] Не удалось скачать OISD: {last_err}")


def hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_raw(
    raw: str,
    min_domains: int = 1,
    exclude: set[str] | None = None,
) -> tuple[list[str], str]:
    lines = raw.splitlines()
    domains = normalize_domains(lines, exclude=exclude)
    if len(domains) < max(1, min_domains):
        raise OISDError(
            f"[ERROR] После обработки доменов {len(domains)} < минимума {min_domains} — "
            "возможно, источник повреждён/подменён"
        )
    digest = hashlib.sha256("\n".join(domains).encode("utf-8")).hexdigest()
    return domains, digest


def load_and_normalize(
    url: str,
    min_domains: int = 1,
    exclude: set[str] | None = None,
) -> tuple[list[str], str]:
    raw = fetch_oisd_raw(url)
    return normalize_raw(raw, min_domains=min_domains, exclude=exclude)
