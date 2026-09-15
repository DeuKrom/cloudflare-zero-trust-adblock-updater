from __future__ import annotations

import re
import time
from typing import Any

import httpx

ACCOUNT_ID_RE = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)


class CloudflareError(RuntimeError):
    pass


def _validate_account_id(account_id: str) -> None:
    if not ACCOUNT_ID_RE.match(account_id or ""):
        raise CloudflareError("[ERROR] CLOUDFLARE_ACCOUNT_ID должен быть 32 hex-символами")


class CloudflareClient:
    def __init__(
        self,
        token: str,
        account_id: str,
        dry_run: bool = False,
        retries: int = 3,
    ) -> None:
        _validate_account_id(account_id)
        if not token or len(token) < 20:
            raise CloudflareError("[ERROR] CLOUDFLARE_API_TOKEN выглядит некорректно")
        self.account_id = account_id
        self.dry_run = dry_run
        self.retries = max(0, retries)
        self.base = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"
        self.client = httpx.Client(
            timeout=45.0,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            follow_redirects=False,
        )

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass

    def __enter__(self) -> CloudflareClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        if self.dry_run and method in {"POST", "PUT", "PATCH", "DELETE"}:
            return {"result": None, "success": True, "dry_run": True}
        last_err: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                r = self.client.request(method, f"{self.base}{path}", **kwargs)
            except httpx.TimeoutException as exc:
                last_err = exc
                if attempt < self.retries:
                    time.sleep(min(2**attempt, 8))
                    continue
                raise CloudflareError(f"[ERROR] Cloudflare API timeout: {exc}") from exc
            except httpx.TransportError as exc:
                last_err = exc
                if attempt < self.retries and method == "GET":
                    time.sleep(min(2**attempt, 8))
                    continue
                raise CloudflareError(f"[ERROR] Cloudflare API network: {exc}") from exc

            # Rate-limit / transient 5xx -> retry with Retry-After/backoff.
            if r.status_code == 429 or r.status_code in {500, 502, 503, 504}:
                retry_after: float | None = None
                try:
                    ra = r.headers.get("Retry-After")
                    if ra:
                        retry_after = float(ra)
                except ValueError:
                    retry_after = None
                if attempt < self.retries:
                    time.sleep(retry_after if retry_after else min(2**attempt, 8))
                    continue
            try:
                data = r.json()
            except ValueError as exc:
                raise CloudflareError(
                    f"[ERROR] Cloudflare API вернул не-JSON (HTTP {r.status_code}): {r.text[:300]}"
                ) from exc
            if r.status_code >= 400 or not data.get("success", False):
                err = data.get("errors") or [{"message": r.text[:500]}]
                msg = err[0].get("message", "Unknown Cloudflare API error") if isinstance(err[0], dict) else str(err[0])
                # 4xx (кроме 429) не ретраим — это ошибка запроса/прав.
                raise CloudflareError(f"[ERROR] Cloudflare API: {msg} (HTTP {r.status_code})")
            return data
        raise CloudflareError(f"[ERROR] Cloudflare API недоступен после ретраев: {last_err}")

    def _paginate(self, path: str) -> list[dict[str, Any]]:
        """Fetch all pages (Cloudflare result_info pagination)."""
        out: list[dict[str, Any]] = []
        page = 1
        per_page = 100
        while True:
            sep = "&" if "?" in path else "?"
            data = self._request("GET", f"{path}{sep}page={page}&per_page={per_page}")
            result = data.get("result") or []
            if isinstance(result, dict):
                # Некоторые endpoints возвращают объект вместо списка.
                out.append(result)
                break
            out.extend(result)
            info = data.get("result_info") or {}
            total_pages = info.get("total_pages") or info.get("totalPages")
            try:
                total_pages = int(total_pages) if total_pages else None
            except (TypeError, ValueError):
                total_pages = None
            if total_pages is not None:
                if page >= total_pages:
                    break
            else:
                # Fallback: последняя страница, если вернулось меньше per_page.
                if len(result) < per_page:
                    break
                # Защита от бесконечного цикла.
                if page > 1000:
                    break
            page += 1
        return out

    def list_gateway_lists(self) -> list[dict[str, Any]]:
        return self._paginate("/lists")

    def list_gateway_rules(self) -> list[dict[str, Any]]:
        return self._paginate("/rules")

    def create_gateway_list(self, name: str, description: str, items: list[dict[str, str]], type_: str = "DOMAIN") -> dict[str, Any]:
        payload = {"name": name, "description": description, "type": type_, "items": items}
        return self._request("POST", "/lists", json=payload).get("result", {})

    def update_gateway_list(self, list_id: str, name: str, description: str, items: list[dict[str, str]], type_: str = "DOMAIN") -> dict[str, Any]:
        payload = {"name": name, "description": description, "type": type_, "items": items}
        return self._request("PUT", f"/lists/{list_id}", json=payload).get("result", {})

    def delete_gateway_list(self, list_id: str) -> None:
        self._request("DELETE", f"/lists/{list_id}")

    def list_gateway_rules_raw(self) -> list[dict[str, Any]]:
        return self.list_gateway_rules()

    def create_gateway_rule(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/rules", json=payload).get("result", {})

    def update_gateway_rule(self, rule_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("PUT", f"/rules/{rule_id}", json=payload).get("result", {})

    def delete_gateway_rule(self, rule_id: str) -> None:
        self._request("DELETE", f"/rules/{rule_id}")
