from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class ChunkState:
    index: int
    name: str
    cloudflare_list_id: str
    item_count: int
    chunk_hash: str


@dataclass
class RuleState:
    name: str
    cloudflare_rule_id: str
    precedence: int


@dataclass
class AppState:
    managed_by: str = "cf-zt-oisd-sync"
    list_prefix: str = "oisd-small-auto"
    rule_name: str = "OISD Small Auto Block"
    source_url: str = "https://small.oisd.nl"
    chunk_size: int = 1000
    last_sync_at: str | None = None
    source_hash: str | None = None
    raw_source_hash: str | None = None
    domain_count: int = 0
    chunks: list[ChunkState] = field(default_factory=list)
    rule: RuleState | None = None

    @staticmethod
    def now_utc_iso() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
