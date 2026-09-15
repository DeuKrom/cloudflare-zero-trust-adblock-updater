import json

import pytest

from cf_zt_oisd_sync import sync as sync_mod
from cf_zt_oisd_sync.cloudflare import CloudflareError
from cf_zt_oisd_sync.config import Config, ConfigError, load_config, sanitize_env_values, write_env_file
from cf_zt_oisd_sync.models import AppState, ChunkState
from cf_zt_oisd_sync.normalize import normalize_domain_line, normalize_domains
from cf_zt_oisd_sync.oisd import OISDError, normalize_raw, validate_oisd_url
from cf_zt_oisd_sync.state import StateError, read_state, safe_state_path, write_state


def test_oisd_url_requires_https():
    with pytest.raises(OISDError):
        validate_oisd_url("http://small.oisd.nl")
    with pytest.raises(OISDError):
        validate_oisd_url("https://user:pass@small.oisd.nl")
    assert validate_oisd_url("https://small.oisd.nl") == "https://small.oisd.nl"


def test_normalize_ignores_exception_rules():
    assert normalize_domain_line("@@||example.com^") is None
    assert normalize_domain_line("@@||ads.example.com^$important") is None


def test_normalize_hosts_tab_and_inline_comment():
    assert normalize_domain_line("0.0.0.0\tads.example.com") == "ads.example.com"
    assert normalize_domain_line("127.0.0.1  ads.example.com  # comment") == "ads.example.com"
    assert normalize_domain_line("example.com # tracker") == "example.com"
    assert normalize_domain_line("||example.com^$third-party") == "example.com"


def test_normalize_raw_min_domains_guard():
    with pytest.raises(OISDError):
        normalize_raw("only-one.com", min_domains=5000)


def test_allowlist_excludes():
    out = normalize_domains(["a.com", "b.com"], exclude={"a.com"})
    assert out == ["b.com"]


def test_traffic_expression_rejects_injection():
    with pytest.raises(ValueError):
        sync_mod.make_traffic_expression(['a") or (1==1'])
    with pytest.raises(ValueError):
        sync_mod.make_traffic_expression(["a;b"])


def test_diff_against_state():
    st = AppState(
        chunks=[
            ChunkState(index=1, name="p-001", cloudflare_list_id="id1", item_count=1, chunk_hash=sync_mod.chunk_hash(["a.com"])),
        ]
    )
    d = sync_mod.diff_against_state(st, [["a.com"], ["b.com"]])
    assert d["create_lists"] == 1
    assert d["unchanged_lists"] == 1 or d["update_lists"] == 0
    d2 = sync_mod.diff_against_state(st, [["changed.com"]])
    assert d2["update_lists"] == 1


def test_drop_guard():
    cfg = Config(cloudflare_api_token="t" * 30, cloudflare_account_id="a" * 32, max_drop_ratio=0.5)
    # 50% drop ok boundary? 100 -> 60 = 40% drop, no error.
    sync_mod.check_drop_guard(cfg, 100, 60)
    with pytest.raises(RuntimeError):
        sync_mod.check_drop_guard(cfg, 100, 10)
    cfg.force = True
    sync_mod.check_drop_guard(cfg, 100, 10)  # no raise with force


def test_config_rejects_bad_int(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "t" * 30)
    monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "a" * 32)
    monkeypatch.setenv("CHUNK_SIZE", "abc")
    with pytest.raises(ConfigError):
        load_config()


def test_config_rejects_bad_account(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "t" * 30)
    monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "../../etc")
    with pytest.raises(ConfigError):
        load_config()


def test_config_rejects_state_traversal(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "t" * 30)
    monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "a" * 32)
    monkeypatch.setenv("STATE_FILE", "../evil.json")
    with pytest.raises(ConfigError):
        load_config()


def test_env_injection_rejected(tmp_path):
    with pytest.raises(ConfigError):
        sanitize_env_values({"LIST_PREFIX": "a\nEVIL=1"})
    p = tmp_path / ".env"
    write_env_file(p, {"CLOUDFLARE_ACCOUNT_ID": "a" * 32, "A": "1"})
    assert p.exists()


def test_state_traversal_blocked():
    with pytest.raises(StateError):
        safe_state_path("../evil.json")
    with pytest.raises(StateError):
        safe_state_path("/etc/passwd.json")


def test_state_roundtrip_and_corrupt(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    st = AppState(domain_count=2, chunks=[])
    write_state("s.json", st)
    assert read_state("s.json") is not None
    (tmp_path / "s.json").write_text("{bad json", encoding="utf-8")
    with pytest.raises(StateError):
        read_state("s.json")


def test_state_validation_rejects_bad_shape(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "s.json").write_text(json.dumps({"chunks": [{"index": "bad"}]}), encoding="utf-8")
    with pytest.raises(StateError):
        read_state("s.json")


def test_cloudflare_account_validation():
    from cf_zt_oisd_sync.cloudflare import CloudflareClient

    with pytest.raises(CloudflareError):
        CloudflareClient("t" * 30, "bad-id")
