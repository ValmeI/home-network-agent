import json
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from itertools import groupby
from pathlib import Path

import requests
from loguru import logger

from network_analyzer import aggregate, is_covered
from settings import settings


def _auth() -> tuple[str, str] | None:
    return (settings.adguard_username, settings.adguard_password) if settings.adguard_username and settings.adguard_password else None


def _call(method: str, path: str, **kwargs) -> dict | None:
    url = f"{settings.adguard_base_url.rstrip('/')}/{path.lstrip('/')}"
    r = getattr(requests, method)(url, auth=_auth(), timeout=settings.adguard_timeout, **kwargs)
    r.raise_for_status()
    return r.json() if method == "get" else None


def _target(rule: str) -> str | None:
    """Domain of a plain ||domain^ block rule, else None"""
    return rule[2:-1] if rule.startswith("||") and rule.endswith("^") else None


def _fetch_user_rules() -> list[str]:
    """Current AdGuard user rules; a missing key raises, since writing back an empty list would wipe every rule"""
    return _call("get", "/control/filtering/status")["user_rules"]


def _backup_rules(rules: list[str]) -> Path:
    backup_dir = Path(settings.rules_backup_dir)
    backup_dir.mkdir(exist_ok=True)
    path = backup_dir / f"user_rules_{datetime.now():%Y%m%d_%H%M%S_%f}.json"
    path.write_text(json.dumps(rules, indent=1))
    for old in sorted(backup_dir.glob("user_rules_*.json"))[: -settings.rules_backup_keep]:
        old.unlink()
    return path


def _save_rules(old: list[str], new: list[str]) -> None:
    """Back up the current rules, refuse any change that loses an allow rule, then write"""
    lost_allows = [rule for rule in old if rule.startswith("@@") and rule not in new]
    if lost_allows:
        raise RuntimeError(f"Refusing to write AdGuard rules: would remove allow rules {lost_allows}")
    path = _backup_rules(old)
    _call("post", "/control/filtering/set_rules", json={"rules": new})
    logger.info(f"AdGuard rules saved ({len(old)} -> {len(new)}), previous rules backed up to {path}")


def get_custom_rules() -> tuple[set[str], set[str]]:
    """(blocked, allowed) domains from AdGuard custom rules (||domain^ and @@||domain^), from one fetch"""
    rules = _fetch_user_rules()
    blocked = {d for rule in rules if (d := _target(rule))}
    allowed = {d for rule in rules if rule.startswith("@@") and (d := _target(rule[2:]))}
    logger.info(f"Loaded {len(blocked)} custom block rules and {len(allowed)} allow rules from AdGuard")
    return blocked, allowed


REPLACES = " | replaces: "
# comments the agent writes itself; any other comment above a rule (e.g. a user's section header) is left alone
AGENT_COMMENT = re.compile(r"^! \d{4}-\d{2}-\d{2} \d{2}:\d{2} \| ")


def _comment(text: str) -> str:
    """Reason text comes from the LLM: newlines would become extra rules and "|" could fake a replaces: marker"""
    return f"! {datetime.now():%Y-%m-%d %H:%M} | {' '.join(text.split()).replace('|', '/')}"


def _drop_subdomain_rules(rules: list[str], domain: str) -> tuple[list[str], list[str]]:
    """Remove ||sub.domain^ (or wildcard-matched) rules made redundant by ||domain^, plus the agent comment right above each"""
    kept, removed = [], []
    for rule in rules:
        target = _target(rule)
        if target and target != domain and is_covered(target, {domain}):
            if kept and AGENT_COMMENT.match(kept[-1]):
                kept.pop()
            removed.append(rule)
            continue
        kept.append(rule)
    return kept, removed


def block_domains_in_adguard(items: list[tuple[str, str]]) -> list[str]:
    """Add ||domain^ with a comment for each (domain, reason), in one write and one backup; subdomain rules a block
    makes redundant are removed and listed in its comment so a revert can restore them"""
    old = _fetch_user_rules()
    rules, blocked = list(old), []
    for domain, reason in items:
        if f"||{domain}^" in rules or is_covered(domain, blocked):
            logger.info(f"Domain {domain} already blocked")
            continue
        rules, removed = _drop_subdomain_rules(rules, domain)
        comment = _comment(reason[:60])
        if removed:
            logger.info(f"Removing {len(removed)} subdomain rules now covered by {domain}: {', '.join(removed)}")
            comment += REPLACES + " ".join(removed)
        rules += [comment, f"||{domain}^"]
        blocked.append(domain)
    if blocked:
        _save_rules(old, rules)
        logger.success(f"Blocked {len(blocked)} domains: {', '.join(blocked)}")
    return blocked


def unblock_domain_in_adguard(domain: str, blocked_by_list: bool = False) -> bool:
    """Undo a block: an exact ||domain^ rule is removed (restoring the subdomain rules it replaced); a domain still
    blocked through a parent, wildcard or blocklist rule gets one @@||domain^ allow rule, so the rest stays blocked"""
    old = _fetch_user_rules()
    rules = list(old)
    exact = f"||{domain}^"
    if exact in rules:
        i = rules.index(exact)
        comment = rules[i - 1] if i and AGENT_COMMENT.match(rules[i - 1]) else ""
        rules = [rule for j, rule in enumerate(rules) if j != i and not (comment and j == i - 1)]
        restored = [r for r in comment.rsplit(REPLACES, 1)[1].split() if r not in rules] if REPLACES in comment else []
        if restored:
            rules += [_comment(f"restored after reverting {domain}"), *restored]
            logger.info(f"Restoring {len(restored)} rules {domain} had replaced: {', '.join(restored)}")
        logger.success(f"Removed {exact}")

    covering = [t for rule in rules if (t := _target(rule)) and is_covered(domain, {t})]
    if not covering and blocked_by_list:
        covering = ["a blocklist"]
    allow = f"@@||{domain}^"
    if covering and allow not in rules:
        rules += [_comment(f"allowed after revert; blocked by {', '.join(covering)}"), allow]
        logger.success(f"{domain} is still blocked by {', '.join(covering)}; added {allow} so only this host is unblocked")
    if rules == old:
        if allow in old:
            logger.info(f"{domain} already has {allow}")
            return True
        logger.warning(f"Domain {domain} is not blocked by any custom rule (it may come from a blocklist)")
        return False
    _save_rules(old, rules)
    return True


def _parse_time(value: str) -> datetime:
    """AdGuard gives nanoseconds; Python parses at most microseconds"""
    return datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", value))


CACHE_VERSION = 3


def _empty_cache() -> dict:
    return {"version": CACHE_VERSION, "newest": None, "days": {}}


def _load_querylog_cache() -> dict:
    path = Path(settings.querylog_cache_file)
    if not path.exists():
        logger.info(f"No querylog cache at {path}, fetching the full window")
        return _empty_cache()
    cache = json.loads(path.read_text())
    if cache.get("version") != CACHE_VERSION:
        logger.info(f"Querylog cache format changed (v{cache.get('version', 1)} -> v{CACHE_VERSION}), fetching the full window")
        return _empty_cache()
    for day in cache["days"].values():
        day["counts"] = Counter(day["counts"])
        for key in ("clients", "blocked_clients"):
            day[key] = defaultdict(Counter, {d: Counter(c) for d, c in day[key].items()})
    return cache


def _save_querylog_cache(cache: dict) -> None:
    path = Path(settings.querylog_cache_file)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache))
    tmp.replace(path)


def _combine_days(days: dict) -> dict:
    agg = aggregate([])
    for _, day in sorted(days.items()):
        agg["total"] += day["total"]
        agg["blocked"] += day["blocked"]
        agg["counts"].update(day["counts"])
        for key in ("clients", "blocked_clients"):
            for domain, clients in day[key].items():
                agg[key][domain].update(clients)
        agg["blocked_rules"].update(day["blocked_rules"])
    return agg


def fetch_adguard_logs() -> dict:
    """Fetch only querylog entries newer than the last run, folded into per-day counts cached on disk; no cache means a full fetch of the window"""
    start = time.monotonic()
    cache = _load_querylog_cache()
    cutoff = datetime.now().astimezone() - timedelta(days=settings.querylog_window_days)
    since = _parse_time(cache["newest"]) if cache["newest"] else None
    if since and since < cutoff:
        logger.info(f"Querylog cache is older than {settings.querylog_window_days} days, fetching the full window")
        cache, since = _empty_cache(), None

    days = cache["days"]
    params = {"limit": settings.adguard_query_limit}
    pages = fetched = 0
    newest = None
    reached_known = False
    while fetched < settings.adguard_max_queries:
        page = _call("get", settings.adguard_querylog, params=params)
        rows = page["data"]
        if not rows:
            break
        newest = newest or rows[0]["time"]
        fresh = []
        for row in rows:
            t = _parse_time(row["time"])
            if (since and t <= since) or t < cutoff:
                reached_known = True
                break
            fresh.append(row)
        for day, day_rows in groupby(fresh, key=lambda row: row["time"][:10]):
            aggregate(list(day_rows), days.setdefault(day, aggregate([])))
        fetched += len(fresh)
        pages += 1
        if pages % 5 == 0:
            logger.info(f"Querylog: {pages} pages, {fetched:,} new queries, back to {rows[-1]['time'][:16]}")
        if reached_known or not page["oldest"] or page["oldest"] == params.get("older_than"):
            break
        params["older_than"] = page["oldest"]
    else:
        raise RuntimeError(
            f"Querylog fetch hit adguard_max_queries={settings.adguard_max_queries:,} before reaching the last run or the window start; "
            "raise it in config.yaml (stopping avoids a permanent gap in the counts)"
        )

    # ponytail: day granularity, so the oldest kept day may hold a few hours beyond the window
    days = {day: counts for day, counts in days.items() if day >= cutoff.date().isoformat()}
    cache = {"version": CACHE_VERSION, "newest": newest or cache["newest"], "days": days}
    _save_querylog_cache(cache)

    agg = _combine_days(days)
    agg["oldest"] = min(days) if days else "?"
    agg["newest"] = cache["newest"] or "?"
    mode = "incremental" if since else "full"
    logger.info(
        f"Querylog {mode} fetch: {fetched:,} new queries in {pages} pages, {time.monotonic() - start:.1f}s. "
        f"Window {agg['oldest']} to {agg['newest'][:16]}: {agg['total']:,} queries"
    )
    return agg
