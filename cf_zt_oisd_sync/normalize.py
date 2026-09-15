from __future__ import annotations

import re

import idna

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


HOSTS_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+(\S+)(?:\s+.*)?$")


class NormalizeError(RuntimeError):
    pass


def _strip_noise(raw: str) -> str:
    s = raw.strip()
    if not s:
        return ""
    # Full-line comments / sections.
    if s.startswith(("#", "!", "[", "]")):
        return ""
    # AdBlock exception rules (@@...) are allowlist entries — never block them.
    if s.startswith("@@"):
        return ""
    # Inline hosts comment: "example.com # tracker" / "0.0.0.0 x.com # comment".
    if "#" in s:
        s = s.split("#", 1)[0].strip()
        if not s:
            return ""
    # Hosts format with any whitespace (space/tab, multiple spaces).
    m = HOSTS_RE.match(s)
    if m:
        s = m.group(1).strip()
    # AdBlock options: "||example.com^$third-party,important" -> cut at $.
    if "$" in s:
        s = s.split("$", 1)[0]
    s = s.replace("^", "")
    # URL path/query: "example.com/path?q=1" -> "example.com".
    if "/" in s:
        s = s.split("/", 1)[0]
    s = s.strip()
    while s.startswith("||"):
        s = s[2:]
    s = s.lstrip("|")
    if s.startswith("*."):
        s = s[2:]
    s = s.strip().strip(".").lower()
    return s


def normalize_domain_line(raw: str) -> str | None:
    s = _strip_noise(raw)
    if not s:
        return None
    if any(token in s for token in [" ", "\t", "@", "["]):
        return None

    if s.isascii():
        ascii_domain = s
    else:
        try:
            ascii_domain = idna.encode(s).decode("ascii")
        except idna.IDNAError:
            return None

    if not DOMAIN_RE.match(ascii_domain):
        return None
    return ascii_domain


def normalize_domains(lines: list[str], exclude: set[str] | None = None) -> list[str]:
    out: set[str] = set()
    for line in lines:
        val = normalize_domain_line(line)
        if val:
            if exclude and val in exclude:
                continue
            out.add(val)
    return sorted(out)


def chunk_domains(domains: list[str], chunk_size: int) -> list[list[str]]:
    if chunk_size <= 0:
        raise NormalizeError("chunk_size должен быть > 0")
    return [domains[i : i + chunk_size] for i in range(0, len(domains), chunk_size)]
