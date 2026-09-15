from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskID, TextColumn, TimeElapsedColumn
from rich.table import Table

from . import __version__
from .cloudflare import CloudflareClient, CloudflareError
from .config import ConfigError, load_config, write_env_file
from .models import AppState
from .oisd import OISDError
from .state import StateError, delete_state, read_state, state_lock
from .sync import (
    MANAGED_MARKER,
    collect_remote_managed,
    diff_against_state,
    get_orphan_rules_by_prefix,
    get_orphans_by_prefix,
    init_sync,
    is_managed_list,
    is_prefix_list,
    plan,
    status_sync,
    update_sync,
)

app = typer.Typer(help="cf-zt-oisd-sync — синхронизация OISD small с Cloudflare Zero Trust Gateway")
console = Console()

EXIT_OK = 0
EXIT_CHECK_FAIL = 1
EXIT_CONFIG = 2
EXIT_CONFIRM = 6
EXIT_DRIFT = 7


def _as_json(data: dict) -> None:
    print(json.dumps(data, ensure_ascii=False))


def _print_state_summary(state: AppState, state_file: str) -> None:
    console.print("Готово.")
    console.print(f"Списков: {len(state.chunks)}")
    console.print(f"Доменов: {state.domain_count}")
    console.print(f"State-файл: {state_file}")


def _update_available_text(info: dict) -> str:
    if info.get("state_error"):
        return f"[red]state повреждён[/red] ({info['state_error']})"
    if info["source_check_error"]:
        return f"[red]не удалось проверить[/red] ({info['source_check_error']})"
    if info["update_available"] is None:
        return "[yellow]неизвестно[/yellow]"
    return "[yellow]доступно[/yellow]" if info["update_available"] else "[green]не требуется[/green]"


def _run_with_progress(operation):
    task_ids: dict[str, TaskID] = {}
    labels = {
        "lists": "Списки Cloudflare",
        "rule": "DNS Gateway rule",
    }

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress_bar:

        def on_progress(kind: str, completed: int, total: int) -> None:
            if kind not in task_ids:
                task_ids[kind] = progress_bar.add_task(labels.get(kind, kind), total=max(total, 1))
            progress_bar.update(task_ids[kind], completed=completed, total=max(total, 1))

        return operation(on_progress)


@app.command("setup")
def setup_cmd() -> None:
    account = typer.prompt("Введите Cloudflare Account ID").strip()
    token = typer.prompt("Введите Cloudflare API Token", hide_input=True).strip()
    source = typer.prompt("Источник OISD small", default="https://small.oisd.nl").strip()
    prefix = typer.prompt("Префикс списков", default="oisd-small-auto").strip()
    rule_name = typer.prompt("Название правила", default="OISD Small Auto Block").strip()
    chunk = typer.prompt("Размер части списка", default="1000").strip()
    if chunk and not chunk.isdigit():
        console.print("[red][ERROR][/red] Размер части должен быть числом")
        raise typer.Exit(EXIT_CONFIG)
    try:
        write_env_file(
            ".env",
            {
                "CLOUDFLARE_ACCOUNT_ID": account,
                "CLOUDFLARE_API_TOKEN": token,
                "OISD_SOURCE_URL": source,
                "LIST_PREFIX": prefix,
                "RULE_NAME": rule_name,
                "CHUNK_SIZE": chunk or "1000",
                "LIST_WORKERS": "4",
                "RULE_PRECEDENCE": "5000",
                "STATE_FILE": ".cf-zt-oisd-state.json",
                "DRY_RUN": "false",
                "LANGUAGE": "en",
                "MIN_DOMAINS": "5000",
                "MAX_DROP_RATIO": "0.5",
                "MAX_LISTS": "500",
                "ALLOWLIST": "",
            },
        )
    except ConfigError as exc:
        console.print(f"[red][ERROR][/red] {exc}")
        raise typer.Exit(EXIT_CONFIG)
    console.print("[green][OK][/green] Файл .env создан (0600).")
    console.print("Следующий шаг: cf-zt-oisd-sync check")


@app.command("menu")
def menu_cmd() -> None:
    """Запустить интерактивное меню с выбором действий по цифрам."""
    from .menu import start_menu

    start_menu()


@app.command("version")
def version_cmd() -> None:
    console.print(f"cf-zt-oisd-sync {__version__}")


@app.command("check")
def check_cmd(json_out: bool = typer.Option(False, "--json")) -> None:
    checks: list[tuple[str, bool]] = []
    checks.append((".env найден", Path(".env").exists()))

    try:
        cfg = load_config(require_cloudflare=True)
    except ConfigError as exc:
        if json_out:
            _as_json({"success": False, "command": "check", "error": str(exc), "exit_code": EXIT_CONFIG})
            raise typer.Exit(EXIT_CONFIG)
        raise

    checks.append(("Cloudflare Account ID найден", bool(cfg.cloudflare_account_id)))
    checks.append(("API token найден", bool(cfg.cloudflare_api_token)))
    checks.append(("OISD URL https", cfg.oisd_source_url.startswith("https://")))

    cf_err = None
    try:
        cf = CloudflareClient(cfg.cloudflare_api_token, cfg.cloudflare_account_id)
        try:
            cf.list_gateway_lists()
            cf.list_gateway_rules()
            checks.append(("Cloudflare API доступен", True))
            checks.append(("Доступ к Gateway Lists/Rules есть", True))
        finally:
            cf.close()
    except Exception as exc:  # noqa: BLE001
        cf_err = str(exc)
        checks.append(("Cloudflare API доступен", False))
        checks.append(("Доступ к Gateway Lists/Rules есть", False))

    try:
        domains, _, _ = plan(cfg)
        checks.append(("OISD small доступен", True))
        checks.append((f"Доменов после обработки: {len(domains)}", len(domains) >= cfg.min_domains))
    except OISDError:
        checks.append(("OISD small доступен", False))
        checks.append(("Доменов после обработки: 0", False))

    success = all(ok for _, ok in checks)
    if json_out:
        _as_json({"success": success, "command": "check", "checks": checks, "cloudflare_error": cf_err})
        raise typer.Exit(EXIT_OK if success else EXIT_CHECK_FAIL)

    console.print("Проверка конфигурации")
    for text, ok in checks:
        marker = "[OK]" if ok else "[ERROR]"
        style = "green" if ok else "red"
        console.print(f"[{style}]{marker}[/{style}] {text}")


@app.command("dry-run")
def dry_run_cmd(json_out: bool = typer.Option(False, "--json")) -> None:
    cfg = load_config(require_cloudflare=True)
    cfg.dry_run = True

    domains, _, chunks = plan(cfg)
    try:
        existing_state = read_state(cfg.state_file)
    except StateError:
        existing_state = None
    cf = CloudflareClient(cfg.cloudflare_api_token, cfg.cloudflare_account_id, dry_run=False)
    try:
        remote_lists, remote_rules = collect_remote_managed(cfg, cf)
    finally:
        cf.close()

    diff = diff_against_state(existing_state, chunks)
    if diff.get("mode") == "no-state":
        # Без state — честно помечаем как оценку по remote, а не точный update.
        plan_data = {
            "create_lists": max(len(chunks) - len(remote_lists), 0),
            "update_lists": 0,
            "unchanged_lists": 0,
            "delete_lists": max(len(remote_lists) - len(chunks), 0),
            "estimated": True,
            "create_rule": 1 if not remote_rules else 0,
        }
    else:
        plan_data = {
            "create_lists": diff["create_lists"],
            "update_lists": diff["update_lists"],
            "unchanged_lists": diff["unchanged_lists"],
            "delete_lists": diff["delete_lists"],
            "estimated": False,
            "create_rule": 1 if not remote_rules else 0,
        }
    payload = {
        "success": True,
        "command": "dry-run",
        "source": cfg.oisd_source_url,
        "domain_count": len(domains),
        "chunk_count": len(chunks),
        "chunk_size": cfg.chunk_size,
        "plan": plan_data,
    }
    if json_out:
        _as_json(payload)
        return

    console.print("Предварительный просмотр изменений")
    console.print(f"Источник: {cfg.oisd_source_url}")
    console.print(f"Доменов после очистки: {len(domains)}")
    console.print(f"Размер части: {cfg.chunk_size}")
    console.print(f"Нужно списков Cloudflare: {len(chunks)}")
    console.print("План действий:")
    console.print(f"+ Создать списков: {plan_data['create_lists']}")
    console.print(f"~ Обновить списков: {plan_data['update_lists']}")
    if "unchanged_lists" in plan_data:
        console.print(f"= Без изменений: {plan_data['unchanged_lists']}")
    console.print(f"- Удалить лишних списков: {plan_data['delete_lists']}")
    console.print(f"+ Создать DNS rule: {'да' if plan_data['create_rule'] else 'нет'}")
    if plan_data.get("estimated"):
        console.print("[yellow]Оценка без state-файла: update/unchanged неизвестны.[/yellow]")
    console.print("Изменения НЕ будут применены.")


@app.command("init")
def init_cmd(
    yes: bool = typer.Option(False, "--yes"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    force: bool = typer.Option(False, "--force", help="Игнорировать guard-ы (precedence/drop/limits)"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    cfg = load_config(require_cloudflare=True)
    cfg.dry_run = dry_run or cfg.dry_run
    cfg.force = force or cfg.force

    if not yes and not cfg.dry_run:
        typer.confirm("Будут созданы Cloudflare lists и DNS rule. Продолжить?", abort=True)

    if json_out:
        state = init_sync(cfg, yes=yes)
    else:
        state = _run_with_progress(lambda progress: init_sync(cfg, yes=yes, progress=progress))
    if json_out:
        _as_json({"success": True, "command": "init", "domain_count": state.domain_count, "chunk_count": len(state.chunks)})
        return
    _print_state_summary(state, cfg.state_file)


@app.command("update")
def update_cmd(
    yes: bool = typer.Option(False, "--yes"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    force: bool = typer.Option(False, "--force", help="Игнорировать guard-ы (precedence/drop/limits)"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    cfg = load_config(require_cloudflare=True)
    cfg.dry_run = dry_run or cfg.dry_run
    cfg.force = force or cfg.force

    if not yes and not cfg.dry_run and not os.isatty(0):
        msg = "[ERROR] Требуется подтверждение, но программа запущена в неинтерактивном режиме. Добавьте --yes."
        if json_out:
            _as_json({"success": False, "command": "update", "error": msg, "exit_code": EXIT_CONFIRM})
        else:
            console.print(f"[red]{msg}[/red]")
        raise typer.Exit(EXIT_CONFIRM)

    if json_out:
        state = update_sync(cfg)
    else:
        state = _run_with_progress(lambda progress: update_sync(cfg, progress=progress))
    if json_out:
        _as_json({"success": True, "command": "update", "domain_count": state.domain_count, "chunk_count": len(state.chunks)})
        return
    _print_state_summary(state, cfg.state_file)


@app.command("status")
def status_cmd(
    json_out: bool = typer.Option(False, "--json"),
    offline: bool = typer.Option(False, "--offline", help="Не ходить в OISD/Cloudflare, только state"),
) -> None:
    cfg = load_config(require_cloudflare=True)
    if offline:
        try:
            state = read_state(cfg.state_file)
            info = {
                "state": state,
                "state_error": None,
                "managed_lists_count": -1,
                "rule_found": False,
                "rule_enabled": False,
                "state_ok": False,
                "missing_in_remote": [],
                "extra_in_remote": [],
                "update_available": None,
                "latest_source_hash": None,
                "latest_domain_count": None,
                "source_check_error": "offline mode",
            }
        except StateError as exc:
            state = None
            info = {
                "state": None,
                "state_error": str(exc),
                "managed_lists_count": -1,
                "rule_found": False,
                "rule_enabled": False,
                "state_ok": False,
                "missing_in_remote": [],
                "extra_in_remote": [],
                "update_available": None,
                "latest_source_hash": None,
                "latest_domain_count": None,
                "source_check_error": "offline mode",
            }
    else:
        info = status_sync(cfg)
    state = info["state"]

    if json_out:
        _as_json(
            {
                "success": True,
                "command": "status",
                "domain_count": state.domain_count if state else 0,
                "chunk_count": len(state.chunks) if state else 0,
                "cloudflare_lists_found": info["managed_lists_count"],
                "rule_found": info["rule_found"],
                "rule_enabled": info["rule_enabled"],
                "state_ok": info["state_ok"],
                "state_error": info.get("state_error"),
                "update_available": info["update_available"],
                "latest_domain_count": info["latest_domain_count"],
                "source_check_error": info["source_check_error"],
                "missing_in_remote": info["missing_in_remote"],
                "extra_in_remote": info["extra_in_remote"],
            }
        )
        raise typer.Exit(EXIT_OK if info["state_ok"] else EXIT_DRIFT)

    console.print("Статус cf-zt-oisd-sync")
    console.print("Конфигурация:")
    console.print(f"Источник OISD: {cfg.oisd_source_url}")
    console.print(f"Префикс списков: {cfg.list_prefix}")
    console.print(f"Название правила: {cfg.rule_name}")
    console.print(f"Размер части: {cfg.chunk_size}")
    if info.get("state_error"):
        console.print(f"[red][ERROR][/red] {info['state_error']}")

    if state:
        table = Table(title="Локальное состояние")
        table.add_column("Параметр")
        table.add_column("Значение")
        table.add_row("State-файл", "найден")
        table.add_row("Последняя синхронизация", str(state.last_sync_at))
        table.add_row("Доменов", str(state.domain_count))
        table.add_row("Списков в state", str(len(state.chunks)))
        table.add_row("Обновление списка", _update_available_text(info))
        if info["latest_domain_count"] is not None:
            table.add_row("Доменов в текущем OISD", str(info["latest_domain_count"]))
        console.print(table)
    else:
        console.print("[yellow][WARNING][/yellow] State-файл не найден/повреждён")
        console.print(f"Обновление списка: {_update_available_text(info)}")

    if not offline:
        console.print("Cloudflare:")
        console.print(f"Найдено managed lists: {info['managed_lists_count']}")
        console.print(f"DNS rule найдено: {'да' if info['rule_found'] else 'нет'}")
        console.print(f"DNS rule включено: {'да' if info['rule_enabled'] else 'нет'}")

        if info["state_ok"]:
            console.print("[green][OK][/green] Локальное состояние совпадает с Cloudflare")
        else:
            console.print("[yellow][WARNING][/yellow] Есть расхождение state и Cloudflare")
            if info["missing_in_remote"]:
                console.print(f"Отсутствуют в Cloudflare: {len(info['missing_in_remote'])}")
            if info["extra_in_remote"]:
                console.print(f"Лишние в Cloudflare: {len(info['extra_in_remote'])}")
            raise typer.Exit(EXIT_DRIFT)


def _classify_deletions(
    all_lists: list[dict], all_rules: list[dict], cfg, state
) -> tuple[list[dict], list[dict], list[dict], list[dict], list[dict], list[dict]]:
    state_list_ids = {c.cloudflare_list_id for c in state.chunks} if state else set()
    state_rule_id = state.rule.cloudflare_rule_id if state and state.rule else None

    managed_lists = [x for x in all_lists if is_managed_list(x, cfg.list_prefix)]
    # State-only, но без маркера — подозрительные, удаляем только с --force.
    state_only_lists = [
        x for x in all_lists if x.get("id") in state_list_ids and x not in managed_lists
    ]
    # Orphans by prefix: любые с префиксом но без маркера (потерян state, ручное удаление маркера и т.д.)
    orphans_by_prefix = get_orphans_by_prefix(all_lists, cfg.list_prefix)
    # Убираем дубли state_only из orphans, чтобы не считать дважды в статистике skip.
    # Но для удаления --include-orphans берем полный список orphans_by_prefix.
    managed_rules = [
        x
        for x in all_rules
        if x.get("name") == cfg.rule_name and MANAGED_MARKER in str(x.get("description", ""))
    ]
    state_only_rules: list[dict] = []
    if state_rule_id:
        for x in all_rules:
            if x.get("id") == state_rule_id and x not in managed_rules:
                # Требуем маркер даже для state-ID, иначе — только --force.
                if MANAGED_MARKER in str(x.get("description", "")):
                    managed_rules.append(x)
                else:
                    state_only_rules.append(x)
    # Orphan rules that reference our lists but not managed (блокируют удаление списков)
    list_ids = {str(x.get("id")) for x in all_lists if is_prefix_list(x, cfg.list_prefix)}
    orphan_rules = get_orphan_rules_by_prefix(all_rules, cfg.list_prefix, list_ids, cfg.rule_name)
    return managed_lists, state_only_lists, orphans_by_prefix, managed_rules, state_only_rules, orphan_rules


@app.command("delete")
def delete_cmd(
    yes: bool = typer.Option(False, "--yes"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    force: bool = typer.Option(False, "--force", help="Удалить и state-only объекты без маркера"),
    include_orphans: bool = typer.Option(
        False, "--include-orphans", "--by-prefix", help="Удалить также сироты по префиксу без маркера (осиротевшие списки)"
    ),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    cfg = load_config(require_cloudflare=True)
    try:
        state = read_state(cfg.state_file)
    except StateError as exc:
        if json_out:
            _as_json({"success": False, "command": "delete", "error": str(exc), "exit_code": EXIT_CONFIG})
            raise typer.Exit(EXIT_CONFIG)
        raise

    cf = CloudflareClient(cfg.cloudflare_api_token, cfg.cloudflare_account_id, dry_run=dry_run)
    try:
        all_lists = cf.list_gateway_lists()
        all_rules = cf.list_gateway_rules()
        managed_lists, state_only_lists, orphans_by_prefix, managed_rules, state_only_rules, orphan_rules = _classify_deletions(
            all_lists, all_rules, cfg, state
        )
        # Orphans: без маркера но с префиксом, исключая уже посчитанные strict.
        # Для --include-orphans берем весь orphans_by_prefix (дедуп с managed).
        # state_only уже внутри orphans_by_prefix, поэтому при include_orphans не добавляем state_only отдельно.
        # Сироты по префиксу — теперь удаляются по умолчанию (пользователь ожидает чистки oisd-small-auto-*).
        # Флаг --include-orphans оставлен для совместимости, но по факту orphans всегда включаются.
        # Авто-включение остаётся для логирования.
        auto_include_orphans = bool(orphans_by_prefix and not managed_lists)
        effective_include_orphans = True  # всегда чистим prefix-орphans, т.к. зависшие списки вида oisd-small-auto-001 должны удаляться
        if True:
            if auto_include_orphans and not include_orphans:
                console.print(f"[yellow]Найдены сироты по префиксу '{cfg.list_prefix}': {len(orphans_by_prefix)} — будут удалены вместе с managed.[/yellow]")
            # Все сироты по префиксу + state_only (дедуп ниже)
            extra_lists = orphans_by_prefix + ([x for x in state_only_lists if x not in orphans_by_prefix] if force else [])
            extra_lists_ids = {x.get("id") for x in extra_lists}
        else:
            extra_lists = state_only_lists if force else []
        extra_rules = state_only_rules if force else []
        # orphan rules всегда включаем (блокируют удаление списков)
        if orphan_rules:
            extra_rules = list({r.get("id"): r for r in (extra_rules + orphan_rules)}.values())
            if not dry_run and not yes:
                console.print(f"[yellow]Сироты-rules (ссылаются на префиксные списки): {len(orphan_rules)} — будут удалены[/yellow]")
                for r in orphan_rules[:5]:
                    console.print(f"  orphan rule {r.get('name')} id={r.get('id')}")
        total_lists = managed_lists + [x for x in extra_lists if x not in managed_lists]
        # Дедуп по id на случай пересечения
        seen = set()
        deduped = []
        for x in total_lists:
            lid = x.get("id")
            if lid not in seen:
                seen.add(lid)
                deduped.append(x)
        total_lists = deduped
        total_rules = managed_rules + extra_rules

        # Подсчет сколько сирот пропущено
        orphans_skipped = len([x for x in orphans_by_prefix if x not in total_lists])

        if not yes and not dry_run:
            console.print("Будут удалены:")
            for r in managed_rules:
                console.print(f"  rule {r.get('name')} id={r.get('id')}")
            console.print(f"DNS rules (managed): {len(managed_rules)}")
            for lst in managed_lists[:20]:
                console.print(f"  list {lst.get('name')} id={lst.get('id')}")
            if len(managed_lists) > 20:
                console.print(f"  ... и ещё {len(managed_lists) - 20}")
            console.print(f"Cloudflare lists (managed): {len(managed_lists)}")
            if state_only_lists or state_only_rules:
                console.print(
                    f"[yellow]State-only без маркера (не будут удалены без --force): "
                    f"lists={len(state_only_lists)} rules={len(state_only_rules)}[/yellow]"
                )
            if orphans_by_prefix:
                if effective_include_orphans:
                    console.print(f"[yellow]Сироты по префиксу '{cfg.list_prefix}' БУДУТ удалены: {len(orphans_by_prefix)}[/yellow]")
                    for lst in orphans_by_prefix[:20]:
                        console.print(f"  orphan {lst.get('name')} id={lst.get('id')} desc={str(lst.get('description',''))[:60]}")
                    if len(orphans_by_prefix) > 20:
                        console.print(f"  ... и ещё {len(orphans_by_prefix) - 20}")
                else:
                    console.print(
                        f"[yellow]Найдены сироты по префиксу '{cfg.list_prefix}' без маркера (не будут удалены без --include-orphans): "
                        f"{len(orphans_by_prefix)}[/yellow]"
                    )
                    for lst in orphans_by_prefix[:5]:
                        console.print(f"  orphan {lst.get('name')} id={lst.get('id')}")
                    console.print("  Подсказка: cf-zt-oisd-sync delete --include-orphans  (или --by-prefix)")
            console.print(f"[cyan]Итого будет удалено: DNS rules {len(total_rules)}, lists {len(total_lists)} (managed {len(managed_lists)} + orphans {len(total_lists)-len(managed_lists)})[/cyan]")
            if orphans_skipped and not effective_include_orphans:
                console.print(f"[yellow]Пропущены сироты: {orphans_skipped} — добавьте --include-orphans чтобы удалить зависшие {cfg.list_prefix}-*[/yellow]")
            console.print("Это действие нельзя отменить.")
            val = typer.prompt("Type DELETE to confirm")
            if val != "DELETE":
                raise typer.Exit(EXIT_CONFIRM)

        if dry_run:
            console.print("[cyan]Dry-run: удаление не выполнялось.[/cyan]")
            # В dry-run показываем что было бы
            if json_out:
                _as_json(
                    {
                        "success": True,
                        "command": "delete",
                        "rules_deleted": len(total_rules),
                        "lists_deleted": len(total_lists),
                        "state_deleted": False,
                        "dry_run": True,
                        "managed_lists": len(managed_lists),
                        "orphans_by_prefix": len(orphans_by_prefix),
                        "orphans_included": effective_include_orphans,
                        "orphans_skipped": orphans_skipped,
                        "state_only_skipped": len(state_only_lists) + len(state_only_rules) if not force and not effective_include_orphans else 0,
                    }
                )
                return
            console.print(f"Будет удалено DNS rules: {len(total_rules)} (managed {len(managed_rules)})")
            console.print(f"Будет удалено Cloudflare lists: {len(total_lists)} (managed {len(managed_lists)}, orphans {len(total_lists)-len(managed_lists)})")
            if orphans_skipped:
                console.print(f"[yellow]Пропущены сироты: {orphans_skipped} (добавьте --include-orphans чтобы удалить {cfg.list_prefix}-*)[/yellow]")
            return
        else:
            failed = []
            delete_workers = min(8, max(1, cfg.list_workers))
            with state_lock(cfg.state_file, timeout=10.0):
                # Правила — последовательно (их 1-2), списки — параллельно 8 потоков
                for r in total_rules:
                    try:
                        cf.delete_gateway_rule(r["id"])
                        console.print(f"  deleted rule {r.get('name')} {r.get('id')}")
                    except Exception as exc:
                        failed.append(f"rule {r.get('id')}: {exc}")
                        console.print(f"[red]Не удалось удалить rule {r.get('id')}: {exc}[/red]")
                if total_lists:
                    # Прогресс-бар для параллельного удаления
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TextColumn("{task.completed}/{task.total}"),
                        TimeElapsedColumn(),
                        console=console,
                    ) as progress:
                        task = progress.add_task(f"Удаление {len(total_lists)} списков (workers={delete_workers})", total=len(total_lists))
                        with ThreadPoolExecutor(max_workers=delete_workers) as executor:
                            futures = {executor.submit(cf.delete_gateway_list, lst["id"]): lst for lst in total_lists}
                            for future in as_completed(futures):
                                lst = futures[future]
                                try:
                                    future.result()
                                    console.print(f"  deleted list {lst.get('name')} {lst.get('id')}")
                                except Exception as exc:
                                    if "404" in str(exc) or "not found" in str(exc).lower():
                                        console.print(f"[yellow]Уже удалён {lst.get('name')}: {exc}[/yellow]")
                                    else:
                                        failed.append(f"list {lst.get('id')}: {exc}")
                                        console.print(f"[red]Не удалось удалить list {lst.get('name')} {lst.get('id')}: {exc}[/red]")
                                progress.advance(task, 1)
                removed_state = delete_state(cfg.state_file)
            console.print("Удаление завершено.")
            console.print(f"Удалено DNS rules: {len(total_rules) - len([f for f in failed if f.startswith('rule')])}/{len(total_rules)}")
            console.print(f"Удалено Cloudflare lists: {len(total_lists) - len([f for f in failed if f.startswith('list')])}/{len(total_lists)} (managed {len(managed_lists)}, orphans {len(total_lists)-len(managed_lists)})")
            console.print(f"State-файл удалён: {'да' if removed_state else 'нет'}")
            if failed:
                console.print(f"[red]Ошибки удаления ({len(failed)}): {failed[0]}[/red]")
                if json_out:
                    _as_json(
                        {
                            "success": False,
                            "command": "delete",
                            "rules_deleted": len(total_rules) - len([f for f in failed if f.startswith('rule')]),
                            "lists_deleted": len(total_lists) - len([f for f in failed if f.startswith('list')]),
                            "state_deleted": removed_state,
                            "errors": failed,
                            "managed_lists": len(managed_lists),
                            "orphans_by_prefix": len(orphans_by_prefix),
                        }
                    )
                    raise typer.Exit(1)
            if orphans_skipped:
                console.print(f"[yellow]Пропущены сироты: {orphans_skipped}[/yellow]")
            if json_out:
                _as_json(
                    {
                        "success": True,
                        "command": "delete",
                        "rules_deleted": len(total_rules),
                        "lists_deleted": len(total_lists),
                        "state_deleted": removed_state,
                        "managed_lists": len(managed_lists),
                        "orphans_by_prefix": len(orphans_by_prefix),
                        "orphans_deleted": len(total_lists) - len(managed_lists),
                        "orphans_skipped": orphans_skipped,
                        "state_only_skipped": len(state_only_lists) + len(state_only_rules) if not force and not effective_include_orphans else 0,
                    }
                )
                return
            return
    finally:
        cf.close()

    # Fallback (не должен достигаться, но для dry-run без cf)
    payload = {
        "success": True,
        "command": "delete",
        "rules_deleted": 0,
        "lists_deleted": 0,
        "state_deleted": False,
        "dry_run": True,
    }
    if json_out:
        _as_json(payload)
        return


@app.command("doctor")
def doctor_cmd(json_out: bool = typer.Option(False, "--json")) -> None:
    cfg = load_config(require_cloudflare=True)
    checks: list[tuple[str, str]] = []

    try:
        state = read_state(cfg.state_file)
    except StateError as exc:
        state = None
        checks.append(("ERROR", str(exc)))

    if state is None and not any(l == "ERROR" for l, _ in checks):
        checks.append(("WARNING", "State-файл не найден"))

    if not cfg.oisd_source_url.startswith("https://"):
        checks.append(("ERROR", "OISD_SOURCE_URL должен быть https://"))
    else:
        checks.append(("OK", "OISD URL использует https"))

    cf_err = None
    managed_lists: list[dict] = []
    managed_rules: list[dict] = []
    try:
        cf = CloudflareClient(cfg.cloudflare_api_token, cfg.cloudflare_account_id)
        try:
            managed_lists, managed_rules = collect_remote_managed(cfg, cf)
        finally:
            cf.close()
    except CloudflareError as exc:
        cf_err = str(exc)
        checks.append(("ERROR", f"Cloudflare API недоступен: {exc}"))

    # Проверка orphans по префиксу (все списки с префиксом, но без маркера)
    try:
        # Нужен полный список, а не только managed
        if cf_err is None:
            cf2 = CloudflareClient(cfg.cloudflare_api_token, cfg.cloudflare_account_id)
            try:
                all_lists_full = cf2.list_gateway_lists()
                orphans = get_orphans_by_prefix(all_lists_full, cfg.list_prefix)
                if orphans:
                    checks.append(("WARNING", f"Найдены сироты по префиксу '{cfg.list_prefix}' без маркера: {len(orphans)} — запустите delete --include-orphans"))
                else:
                    checks.append(("OK", f"Сирот по префиксу '{cfg.list_prefix}' нет"))
            finally:
                cf2.close()
    except Exception:
        pass

    if state and managed_lists:
        remote_ids = {x.get("id") for x in managed_lists}
        state_ids = {c.cloudflare_list_id for c in state.chunks}
        missing = state_ids - remote_ids
        extra = remote_ids - state_ids
        if missing:
            checks.append(("ERROR", f"Не найдены в Cloudflare списки из state: {len(missing)}"))
        else:
            checks.append(("OK", "Все списки из state найдены в Cloudflare"))
        if extra:
            checks.append(("WARNING", f"Найдены лишние managed lists: {len(extra)}"))

    if managed_rules:
        checks.append(("OK", "DNS rule найдено"))
        if not bool(managed_rules[0].get("enabled")):
            checks.append(("WARNING", "DNS rule выключено"))
        else:
            checks.append(("OK", "DNS rule включено"))
    elif cf_err is None:
        checks.append(("WARNING", "DNS rule не найдено"))

    if cfg.allowlist:
        checks.append(("OK", f"Allowlist исключений: {len(cfg.allowlist)}"))

    success = not any(level == "ERROR" for level, _ in checks)

    if json_out:
        _as_json({"success": success, "command": "doctor", "checks": checks})
        raise typer.Exit(EXIT_OK if success else EXIT_DRIFT)

    console.print("Диагностика")
    for level, msg in checks:
        color = {"OK": "green", "WARNING": "yellow", "ERROR": "red"}.get(level, "white")
        console.print(f"[{color}][{level}][/{color}] {msg}")

    if not success:
        console.print("Рекомендация: cf-zt-oisd-sync update --yes")
        raise typer.Exit(EXIT_DRIFT)


@app.callback()
def main() -> None:
    pass
