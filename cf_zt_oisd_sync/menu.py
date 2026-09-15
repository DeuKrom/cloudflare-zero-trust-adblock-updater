from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskID, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from .cloudflare import CloudflareClient
from .config import ConfigError, load_config, write_env_file
from .models import AppState
from .oisd import OISDError
from .state import StateError, delete_state, read_state, state_lock
from .sync import (
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

console = Console()
SUPPORTED_LANGUAGES = {"en", "ru"}

MESSAGES = {
    "en": {
        "pause": "\nPress Enter to return to the menu",
        "done": "Done.",
        "lists_count": "Lists",
        "domains_count": "Domains",
        "state_file": "State file",
        "update_check_failed": "failed to check",
        "update_unknown": "unknown",
        "update_available": "available",
        "update_not_needed": "not needed",
        "progress_lists": "Cloudflare lists",
        "progress_rule": "DNS Gateway rule",
        "prompt_account": "Enter Cloudflare Account ID",
        "prompt_token": "Enter Cloudflare API Token",
        "prompt_source": "OISD small source",
        "prompt_prefix": "List prefix",
        "prompt_rule_name": "Rule name",
        "prompt_chunk": "List chunk size",
        "env_created": ".env file created.",
        "next_step": "Next step: choose option 2 to check the connection.",
        "env_found": ".env found",
        "check_config_title": "Configuration check",
        "account_found": "Cloudflare Account ID found",
        "token_found": "API token found",
        "cf_api_available": "Cloudflare API available",
        "gateway_access": "Gateway Lists/Rules access available",
        "oisd_available": "OISD small available",
        "processed_domains": "Domains after processing",
        "dry_run_title": "Change preview",
        "column_param": "Parameter",
        "column_value": "Value",
        "source": "Source",
        "chunk_size": "Chunk size",
        "needed_lists": "Cloudflare lists needed",
        "create_lists": "+ Lists to create",
        "update_lists": "~ Lists to update",
        "delete_extra_lists": "- Extra lists to delete",
        "create_dns_rule": "+ Create DNS rule",
        "yes": "yes",
        "no": "no",
        "dry_run_info": "Changes will NOT be applied.",
        "init_notice": "Cloudflare DOMAIN lists and a DNS Gateway blocking rule will be created.",
        "continue": "Continue?",
        "operation_cancelled": "Operation cancelled.",
        "sync_notice": "If the lists do not exist yet, they will be created. Existing lists will be updated.",
        "status_title": "cf-zt-oisd-sync status",
        "source_oisd": "OISD source",
        "list_prefix": "List prefix",
        "rule_name": "Rule name",
        "state_title": "State",
        "found": "found",
        "not_found": "not found",
        "last_sync": "Last sync",
        "domains_in_state": "Domains",
        "lists_in_state": "Lists in state",
        "list_update": "List update",
        "latest_oisd_domains": "Domains in current OISD",
        "dns_rule_found": "DNS rule found",
        "dns_rule_enabled": "DNS rule enabled",
        "state_ok": "Local state matches Cloudflare.",
        "state_mismatch": "State and Cloudflare do not match.",
        "will_delete": "Will be deleted:",
        "cannot_undo": "This action cannot be undone.",
        "confirm_delete": "To confirm, type DELETE",
        "delete_done": "Delete completed.",
        "dns_rules_removed": "DNS rules removed",
        "cf_lists_removed": "Cloudflare lists removed",
        "state_removed": "State file removed",
        "state_valid": "State file is valid",
        "state_missing": "State file not found",
        "state_lists_missing": "State lists not found",
        "extra_managed_lists": "Extra managed lists",
        "dns_rule_missing": "DNS rule not found",
        "diagnostics": "Diagnostics",
        "menu_setup": "1. Initial setup (.env)",
        "menu_check": "2. Check Cloudflare and OISD connection",
        "menu_dry_run": "3. Dry-run: show plan without changes",
        "menu_sync": "4. Create or update lists and blocking rule",
        "menu_status": "5. Show status",
        "menu_delete": "6. Delete created objects",
        "menu_doctor": "7. Diagnose problems",
        "menu_language": "8. Language / Язык",
        "menu_exit": "0. Exit",
        "env_missing_warning": ".env file was not found yet. Start with option 1.",
        "choose_action": "Choose an action",
        "exit": "Exit.",
        "unknown_menu_item": "No such menu item.",
        "interrupted": "Operation interrupted by user.",
        "language_title": "Language",
        "language_prompt": "Choose language",
        "language_english": "1. English",
        "language_russian": "2. Русский",
        "language_saved": "Language saved: English.",
    },
    "ru": {
        "pause": "\nНажмите Enter, чтобы вернуться в меню",
        "done": "Готово.",
        "lists_count": "Списков",
        "domains_count": "Доменов",
        "state_file": "State-файл",
        "update_check_failed": "не удалось проверить",
        "update_unknown": "неизвестно",
        "update_available": "доступно",
        "update_not_needed": "не требуется",
        "progress_lists": "Списки Cloudflare",
        "progress_rule": "DNS Gateway rule",
        "prompt_account": "Введите Cloudflare Account ID",
        "prompt_token": "Введите Cloudflare API Token",
        "prompt_source": "Источник OISD small",
        "prompt_prefix": "Префикс списков",
        "prompt_rule_name": "Название правила",
        "prompt_chunk": "Размер части списка",
        "env_created": "Файл .env создан.",
        "next_step": "Следующий шаг: выберите пункт 2, чтобы проверить подключение.",
        "env_found": ".env найден",
        "check_config_title": "Проверка конфигурации",
        "account_found": "Cloudflare Account ID найден",
        "token_found": "API token найден",
        "cf_api_available": "Cloudflare API доступен",
        "gateway_access": "Доступ к Gateway Lists/Rules есть",
        "oisd_available": "OISD small доступен",
        "processed_domains": "Доменов после обработки",
        "dry_run_title": "Предварительный просмотр изменений",
        "column_param": "Параметр",
        "column_value": "Значение",
        "source": "Источник",
        "chunk_size": "Размер части",
        "needed_lists": "Нужно списков Cloudflare",
        "create_lists": "+ Создать списков",
        "update_lists": "~ Обновить списков",
        "delete_extra_lists": "- Удалить лишних списков",
        "create_dns_rule": "+ Создать DNS rule",
        "yes": "да",
        "no": "нет",
        "dry_run_info": "Изменения НЕ будут применены.",
        "init_notice": "Будут созданы Cloudflare DOMAIN lists и DNS Gateway blocking rule.",
        "continue": "Продолжить?",
        "operation_cancelled": "Операция отменена.",
        "sync_notice": "Если списки ещё не созданы, они будут созданы. Если уже есть — будут обновлены.",
        "status_title": "Статус cf-zt-oisd-sync",
        "source_oisd": "Источник OISD",
        "list_prefix": "Префикс списков",
        "rule_name": "Название правила",
        "state_title": "Состояние",
        "found": "найден",
        "not_found": "не найден",
        "last_sync": "Последняя синхронизация",
        "domains_in_state": "Доменов",
        "lists_in_state": "Списков в state",
        "list_update": "Обновление списка",
        "latest_oisd_domains": "Доменов в текущем OISD",
        "dns_rule_found": "DNS rule найдено",
        "dns_rule_enabled": "DNS rule включено",
        "state_ok": "Локальное состояние совпадает с Cloudflare.",
        "state_mismatch": "Есть расхождение state и Cloudflare.",
        "will_delete": "Будут удалены:",
        "cannot_undo": "Это действие нельзя отменить.",
        "confirm_delete": "Чтобы подтвердить, введите DELETE",
        "delete_done": "Удаление завершено.",
        "dns_rules_removed": "Удалено DNS rules",
        "cf_lists_removed": "Удалено Cloudflare lists",
        "state_removed": "State-файл удалён",
        "state_valid": "State-файл валиден",
        "state_missing": "State-файл не найден",
        "state_lists_missing": "Списков из state не найдено",
        "extra_managed_lists": "Лишних managed lists",
        "dns_rule_missing": "DNS rule не найдено",
        "diagnostics": "Диагностика",
        "menu_setup": "1. Первичная настройка (.env)",
        "menu_check": "2. Проверить подключение Cloudflare и OISD",
        "menu_dry_run": "3. Dry-run: показать план без изменений",
        "menu_sync": "4. Создать или обновить списки и правило блокировки",
        "menu_status": "5. Показать статус",
        "menu_delete": "6. Удалить созданные объекты",
        "menu_doctor": "7. Диагностика проблем",
        "menu_language": "8. Language / Язык",
        "menu_exit": "0. Выход",
        "env_missing_warning": "Файл .env пока не найден. Начните с пункта 1.",
        "choose_action": "Выберите действие",
        "exit": "Выход.",
        "unknown_menu_item": "Такого пункта нет.",
        "interrupted": "Операция прервана пользователем.",
        "language_title": "Язык",
        "language_prompt": "Выберите язык",
        "language_english": "1. English",
        "language_russian": "2. Русский",
        "language_saved": "Язык сохранён: русский.",
    },
}


def _language() -> str:
    try:
        lang = load_config(require_cloudflare=False).language.strip().lower()
    except Exception:
        lang = "en"
    return lang if lang in SUPPORTED_LANGUAGES else "en"


def _t(key: str) -> str:
    lang = _language()
    return MESSAGES[lang].get(key, MESSAGES["en"][key])


def _write_language(language: str) -> None:
    import os as _os

    env_path = Path(".env")
    if env_path.exists():
        try:
            lines = env_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        updated = False
        for index, line in enumerate(lines):
            if line.startswith("LANGUAGE="):
                lines[index] = f"LANGUAGE={language}"
                updated = True
                break
        if not updated:
            lines.append(f"LANGUAGE={language}")
        tmp = env_path.with_name(env_path.name + f".tmp-{_os.getpid()}")
        tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            _os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(env_path)
        try:
            _os.chmod(env_path, 0o600)
        except OSError:
            pass
        return
    tmp = env_path.with_name(env_path.name + f".tmp-{_os.getpid()}")
    tmp.write_text(f"LANGUAGE={language}\n", encoding="utf-8")
    try:
        _os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(env_path)


def _pause() -> None:
    Prompt.ask(_t("pause"), default="")


def _print_error(exc: Exception) -> None:
    console.print(f"[red][ERROR][/red] {exc}")


def _print_summary(state: AppState, state_file: str) -> None:
    console.print(f"[green][OK][/green] {_t('done')}")
    console.print(f"{_t('lists_count')}: {len(state.chunks)}")
    console.print(f"{_t('domains_count')}: {state.domain_count}")
    console.print(f"{_t('state_file')}: {state_file}")


def _update_available_text(info: dict) -> str:
    if info["source_check_error"]:
        return f"[red]{_t('update_check_failed')}[/red] ({info['source_check_error']})"
    if info["update_available"] is None:
        return f"[yellow]{_t('update_unknown')}[/yellow]"
    return f"[yellow]{_t('update_available')}[/yellow]" if info["update_available"] else f"[green]{_t('update_not_needed')}[/green]"


def _run_with_progress(operation):
    task_ids: dict[str, TaskID] = {}
    labels = {
        "lists": _t("progress_lists"),
        "rule": _t("progress_rule"),
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


def _setup_env() -> None:
    language = _language()
    account = Prompt.ask(_t("prompt_account")).strip()
    token = Prompt.ask(_t("prompt_token"), password=True).strip()
    source = Prompt.ask(_t("prompt_source"), default="https://small.oisd.nl").strip()
    prefix = Prompt.ask(_t("prompt_prefix"), default="oisd-small-auto").strip()
    rule_name = Prompt.ask(_t("prompt_rule_name"), default="OISD Small Auto Block").strip()
    chunk = Prompt.ask(_t("prompt_chunk"), default="1000").strip()
    if chunk and not chunk.isdigit():
        console.print("[red][ERROR] Chunk size must be a number[/red]")
        return
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
                "RULE_PRECEDENCE": "5000",
                "LIST_WORKERS": "4",
                "STATE_FILE": ".cf-zt-oisd-state.json",
                "DRY_RUN": "false",
                "LANGUAGE": language,
                "MIN_DOMAINS": "5000",
                "MAX_DROP_RATIO": "0.5",
                "MAX_LISTS": "500",
                "ALLOWLIST": "",
            },
        )
    except Exception as exc:
        console.print(f"[red][ERROR][/red] {exc}")
        return
    console.print(f"[green][OK][/green] {_t('env_created')}")
    console.print(_t("next_step"))


def _check() -> None:
    checks: list[tuple[str, bool]] = [(_t("env_found"), Path(".env").exists())]

    try:
        cfg = load_config(require_cloudflare=True)
    except ConfigError as exc:
        checks.append((str(exc), False))
        _print_checks(_t("check_config_title"), checks)
        return

    checks.append((_t("account_found"), bool(cfg.cloudflare_account_id)))
    checks.append((_t("token_found"), bool(cfg.cloudflare_api_token)))

    try:
        cf = CloudflareClient(cfg.cloudflare_api_token, cfg.cloudflare_account_id)
        try:
            cf.list_gateway_lists()
            cf.list_gateway_rules()
        finally:
            cf.close()
        checks.append((_t("cf_api_available"), True))
        checks.append((_t("gateway_access"), True))
    except Exception:
        checks.append((_t("cf_api_available"), False))
        checks.append((_t("gateway_access"), False))

    try:
        domains, _, _ = plan(cfg)
        checks.append((_t("oisd_available"), True))
        checks.append((f"{_t('processed_domains')}: {len(domains)}", len(domains) >= 100))
    except OISDError:
        checks.append((_t("oisd_available"), False))
        checks.append((f"{_t('processed_domains')}: 0", False))

    _print_checks(_t("check_config_title"), checks)


def _print_checks(title: str, checks: list[tuple[str, bool]]) -> None:
    console.print(title)
    for text, ok in checks:
        style = "green" if ok else "red"
        marker = "[OK]" if ok else "[ERROR]"
        console.print(f"[{style}]{marker}[/{style}] {text}")


def _dry_run() -> None:
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
        create_n = max(len(chunks) - len(remote_lists), 0)
        update_n = 0
        delete_n = max(len(remote_lists) - len(chunks), 0)
        estimated = True
    else:
        create_n = diff["create_lists"]
        update_n = diff["update_lists"]
        delete_n = diff["delete_lists"]
        estimated = False
    table = Table(title=_t("dry_run_title"))
    table.add_column(_t("column_param"))
    table.add_column(_t("column_value"))
    table.add_row(_t("source"), cfg.oisd_source_url)
    table.add_row(_t("processed_domains"), str(len(domains)))
    table.add_row(_t("chunk_size"), str(cfg.chunk_size))
    table.add_row(_t("needed_lists"), str(len(chunks)))
    table.add_row(_t("create_lists"), str(create_n))
    table.add_row(_t("update_lists"), str(update_n))
    table.add_row(_t("delete_extra_lists"), str(delete_n))
    table.add_row(_t("create_dns_rule"), _t("yes") if not remote_rules else _t("no"))
    console.print(table)
    if estimated:
        console.print("[yellow]Estimate without state file.[/yellow]")
    console.print(f"[cyan][INFO][/cyan] {_t('dry_run_info')}")


def _init() -> None:
    cfg = load_config(require_cloudflare=True)

    console.print(_t("init_notice"))
    if not Confirm.ask(_t("continue"), default=False):
        console.print(f"[yellow][WARNING][/yellow] {_t('operation_cancelled')}")
        return

    state = _run_with_progress(lambda progress: init_sync(cfg, yes=True, progress=progress))
    _print_summary(state, cfg.state_file)


def _sync() -> None:
    cfg = load_config(require_cloudflare=True)
    console.print(_t("sync_notice"))
    if not Confirm.ask(_t("continue"), default=True):
        console.print(f"[yellow][WARNING][/yellow] {_t('operation_cancelled')}")
        return
    state = _run_with_progress(lambda progress: update_sync(cfg, progress=progress))
    _print_summary(state, cfg.state_file)


def _status() -> None:
    cfg = load_config(require_cloudflare=True)
    try:
        info = status_sync(cfg)
    except StateError as exc:
        console.print(f"[red][ERROR][/red] {exc}")
        return
    state = info["state"]
    if info.get("state_error"):
        console.print(f"[red][ERROR][/red] {info['state_error']}")

    console.print(_t("status_title"))
    console.print(f"{_t('source_oisd')}: {cfg.oisd_source_url}")
    console.print(f"{_t('list_prefix')}: {cfg.list_prefix}")
    console.print(f"{_t('rule_name')}: {cfg.rule_name}")
    console.print(f"{_t('chunk_size')}: {cfg.chunk_size}")

    table = Table(title=_t("state_title"))
    table.add_column(_t("column_param"))
    table.add_column(_t("column_value"))
    table.add_row(_t("state_file"), _t("found") if state else _t("not_found"))
    table.add_row(_t("last_sync"), str(state.last_sync_at) if state else "-")
    table.add_row(_t("domains_in_state"), str(state.domain_count) if state else "0")
    table.add_row(_t("lists_in_state"), str(len(state.chunks)) if state else "0")
    table.add_row(_t("list_update"), _update_available_text(info))
    if info["latest_domain_count"] is not None:
        table.add_row(_t("latest_oisd_domains"), str(info["latest_domain_count"]))
    table.add_row("Cloudflare managed lists", str(info["managed_lists_count"]))
    table.add_row(_t("dns_rule_found"), _t("yes") if info["rule_found"] else _t("no"))
    table.add_row(_t("dns_rule_enabled"), _t("yes") if info["rule_enabled"] else _t("no"))
    console.print(table)

    if info["state_ok"]:
        console.print(f"[green][OK][/green] {_t('state_ok')}")
    else:
        console.print(f"[yellow][WARNING][/yellow] {_t('state_mismatch')}")


def _delete() -> None:
    cfg = load_config(require_cloudflare=True)
    try:
        state = read_state(cfg.state_file)
    except StateError as exc:
        console.print(f"[red][ERROR][/red] {exc}")
        return

    cf = CloudflareClient(cfg.cloudflare_api_token, cfg.cloudflare_account_id, dry_run=False)
    try:
        all_lists = cf.list_gateway_lists()
        all_rules = cf.list_gateway_rules()
        # Strict: только объекты с маркером.
        managed_lists = [
            x for x in all_lists if is_managed_list(x, cfg.list_prefix)
        ]
        orphans = get_orphans_by_prefix(all_lists, cfg.list_prefix)
        state_ids = {c.cloudflare_list_id for c in state.chunks} if state else set()
        state_only = [x for x in all_lists if x.get("id") in state_ids and x not in managed_lists]
        managed_rules = [
            x
            for x in all_rules
            if (x.get("name") == cfg.rule_name and "Managed by cf-zt-oisd-sync" in str(x.get("description", "")))
        ]
        # State rule с маркером — тоже managed.
        if state and state.rule:
            for x in all_rules:
                if x.get("id") == state.rule.cloudflare_rule_id and x not in managed_rules:
                    if "Managed by cf-zt-oisd-sync" in str(x.get("description", "")):
                        managed_rules.append(x)
        # Orphan rules that block list deletion (ссылаются на наши списки)
        list_ids = {str(x.get("id")) for x in all_lists if str(x.get("name", "")).startswith(cfg.list_prefix)}
        orphan_rules = get_orphan_rules_by_prefix(all_rules, cfg.list_prefix, list_ids, cfg.rule_name)

        console.print(_t("will_delete"))
        console.print(f"DNS rules: {len(managed_rules)} + orphans {len(orphan_rules)}")
        console.print(f"Cloudflare lists (managed): {len(managed_lists)}")
        if orphans:
            console.print(f"[yellow]Сироты по префиксу '{cfg.list_prefix}' без маркера: {len(orphans)} — будут удалены вместе с managed[/yellow]")
            for lst in orphans[:10]:
                console.print(f"  orphan {lst.get('name')} id={lst.get('id')}")
            if len(orphans) > 10:
                console.print(f"  ... и ещё {len(orphans)-10}")
        if orphan_rules:
            console.print(f"[yellow]Сироты-rules по префиксу: {len(orphan_rules)}[/yellow]")
            for r in orphan_rules[:5]:
                console.print(f"  orphan rule {r.get('name')} id={r.get('id')}")
        if state_only:
            console.print(f"[yellow]State-only без маркера: {len(state_only)}[/yellow]")
        console.print(f"[red]{_t('cannot_undo')}[/red]")
        if Prompt.ask(_t("confirm_delete")) != "DELETE":
            console.print(f"[yellow][WARNING][/yellow] {_t('operation_cancelled')}")
            return

        # Теперь сироты удаляются вместе с managed по умолчанию (пользователь ожидает чистки oisd-small-auto-*) — 8 потоков
        all_to_delete = managed_lists + orphans
        delete_workers = min(8, max(1, cfg.list_workers))
        with state_lock(cfg.state_file, timeout=10.0):
            for rule in managed_rules + orphan_rules:
                try:
                    cf.delete_gateway_rule(rule["id"])
                    console.print(f"  deleted rule {rule.get('name')} {rule.get('id')}")
                except Exception as exc:
                    console.print(f"[red]Не удалось удалить rule {rule.get('id')}: {exc}[/red]")
            if all_to_delete:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("{task.completed}/{task.total}"),
                    TimeElapsedColumn(),
                    console=console,
                ) as progress:
                    task = progress.add_task(f"Удаление {len(all_to_delete)} списков (workers={delete_workers})", total=len(all_to_delete))
                    with ThreadPoolExecutor(max_workers=delete_workers) as executor:
                        futures = {executor.submit(cf.delete_gateway_list, item["id"]): item for item in all_to_delete}
                        for future in as_completed(futures):
                            item = futures[future]
                            try:
                                future.result()
                                console.print(f"  deleted {'orphan' if item in orphans else 'list'} {item.get('name')} {item.get('id')}")
                            except Exception as exc:
                                console.print(f"[red]Не удалось удалить {item.get('name')}: {exc}[/red]")
                            progress.advance(task, 1)
    finally:
        cf.close()

    removed_state = delete_state(cfg.state_file)
    console.print(f"[green][OK][/green] {_t('delete_done')}")
    console.print(f"{_t('dns_rules_removed')}: {len(managed_rules) + len(orphan_rules)}")
    console.print(f"{_t('cf_lists_removed')}: {len(all_to_delete)} (managed {len(managed_lists)} + orphans {len(orphans)})")
    console.print(f"{_t('state_removed')}: {_t('yes') if removed_state else _t('no')}")
    if orphans and not include_orphans:
        console.print(f"[yellow]Пропущены сироты: {len(orphans)} — удалите через CLI: cf-zt-oisd-sync delete --include-orphans[/yellow]")


def _doctor() -> None:
    checks: list[tuple[str, str]] = []
    cfg = load_config(require_cloudflare=True)

    try:
        state = read_state(cfg.state_file)
        checks.append(("OK", _t("state_valid") if state else _t("state_missing")))
    except StateError as exc:
        state = None
        checks.append(("ERROR", str(exc)))

    if not cfg.oisd_source_url.startswith("https://"):
        checks.append(("ERROR", "OISD URL must use https"))
    else:
        checks.append(("OK", "OISD URL uses https"))

    try:
        cf = CloudflareClient(cfg.cloudflare_api_token, cfg.cloudflare_account_id)
    except Exception as exc:
        console.print(_t("diagnostics"))
        console.print(f"[red][ERROR][/red] {exc}")
        return
    try:
        managed_lists, managed_rules = collect_remote_managed(cfg, cf)
        # Также проверим сирот по префиксу
        try:
            all_lists = cf.list_gateway_lists()
            orphans = get_orphans_by_prefix(all_lists, cfg.list_prefix)
            if orphans:
                checks.append(("WARNING", f"Сироты по префиксу '{cfg.list_prefix}' без маркера: {len(orphans)}"))
        except Exception:
            pass
    except Exception as exc:
        checks.append(("ERROR", f"Cloudflare API: {exc}"))
        managed_lists, managed_rules = [], []
    finally:
        try:
            cf.close()
        except Exception:
            pass

    if state:
        remote_ids = {x.get("id") for x in managed_lists}
        state_ids = {c.cloudflare_list_id for c in state.chunks}
        missing = state_ids - remote_ids
        extra = remote_ids - state_ids
        checks.append(("OK" if not missing else "ERROR", f"{_t('state_lists_missing')}: {len(missing)}"))
        checks.append(("OK" if not extra else "WARNING", f"{_t('extra_managed_lists')}: {len(extra)}"))

    checks.append(("OK" if managed_rules else "WARNING", _t("dns_rule_found") if managed_rules else _t("dns_rule_missing")))
    if managed_rules:
        checks.append(("OK" if managed_rules[0].get("enabled") else "WARNING", _t("dns_rule_enabled")))

    console.print(_t("diagnostics"))
    for level, message in checks:
        color = {"OK": "green", "WARNING": "yellow", "ERROR": "red"}.get(level, "white")
        console.print(f"[{color}][{level}][/{color}] {message}")


def _print_menu() -> None:
    console.print(
        Panel.fit(
            "\n".join(
                [
                    _t("menu_setup"),
                    _t("menu_check"),
                    _t("menu_dry_run"),
                    _t("menu_sync"),
                    _t("menu_status"),
                    _t("menu_delete"),
                    _t("menu_doctor"),
                    _t("menu_language"),
                    _t("menu_exit"),
                ]
            ),
            title="cf-zt-oisd-sync",
            border_style="cyan",
        )
    )


def _choose_language() -> None:
    console.print(_t("language_title"))
    console.print(_t("language_english"))
    console.print(_t("language_russian"))
    choice = Prompt.ask(_t("language_prompt"), choices=["1", "2"], default="1")
    language = "en" if choice == "1" else "ru"
    _write_language(language)
    console.print(MESSAGES[language]["language_saved"])


def start_menu() -> None:
    actions = {
        "1": _setup_env,
        "2": _check,
        "3": _dry_run,
        "4": _sync,
        "5": _status,
        "6": _delete,
        "7": _doctor,
        "8": _choose_language,
    }

    while True:
        console.clear()
        if not Path(".env").exists():
            console.print(f"[yellow][WARNING][/yellow] {_t('env_missing_warning')}")
        _print_menu()
        choice = Prompt.ask(_t("choose_action"), default="0").strip()
        if choice == "0":
            console.print(_t("exit"))
            return
        action = actions.get(choice)
        if not action:
            console.print(f"[yellow][WARNING][/yellow] {_t('unknown_menu_item')}")
            _pause()
            continue

        try:
            action()
        except (ConfigError, OISDError, StateError, RuntimeError) as exc:
            _print_error(exc)
        except KeyboardInterrupt:
            console.print(f"\n[yellow][WARNING][/yellow] {_t('interrupted')}")
        _pause()
