import json
import os
import sys
import threading
import time
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime

from loguru import logger
from openai import BadRequestError, OpenAI

from agent_state import reverted_domains
from network_analyzer import family_key, is_covered, is_trusted_domain
from settings import settings

client = OpenAI(api_key=settings.openai_api_key)


@contextmanager
def spinner(messages: list[str]):
    # ponytail: TTY only, so cron/log runs stay clean
    if not sys.stderr.isatty():
        yield
        return
    stop = threading.Event()
    glow = [51, 45, 39, 33, 27]
    reserved = 20 + max(len(m) for m in messages)

    def spin():
        start = time.monotonic()
        last_len = 0
        sys.stderr.write("\033[?25l\033[?7l")
        while True:
            if stop.wait(0.08):
                break
            elapsed = time.monotonic() - start
            cols = os.get_terminal_size(sys.stderr.fileno()).columns or 80
            # terminal reflows the old line onto several rows when the window shrinks
            up = f"\033[{-(-last_len // cols) - 1}A" if last_len > cols else ""
            width = max(10, cols - reserved)
            trail = max(len(glow), width // 8)
            pos = round((1 - abs((elapsed / 1.5) % 2 - 1)) * (width - 1))
            bar = "".join(f"\033[38;5;{glow[abs(i - pos) * len(glow) // trail]}m▰" if abs(i - pos) < trail else "\033[38;5;238m▱" for i in range(width))
            msg = messages[int(elapsed // 3) % len(messages)]
            last_len = 6 + width + 2 + len(msg) + 2 + 5
            sys.stderr.write(f"\r{up}\033[J  🛡️  {bar}\033[0m  \033[1m{msg}\033[0m  \033[2m{int(elapsed) // 60:02d}:{int(elapsed) % 60:02d}\033[0m")
            sys.stderr.flush()
        sys.stderr.write("\r\033[J\033[?7h\033[?25h")

    t = threading.Thread(target=spin, daemon=True)
    t.start()
    try:
        yield
    finally:
        stop.set()
        t.join()


HISTORY_LABELS = {"recommended": "recommended block", "skipped": "user skipped", "watched": "watched", "blocked": "user blocked", "reverted": "reverted"}


def device_label(client: str, devices: dict[str, dict]) -> str:
    """Name from config, else from the router, else devNN from the last address part - raw LAN IPs never reach the LLM"""
    if client in settings.device_names:
        return settings.device_names[client]
    if client in devices:
        return devices[client]["label"]
    if client.count(".") == 3 and client.replace(".", "").isdigit():
        return "dev" + client.rsplit(".", 1)[1]
    return "dev" + client.rsplit(":", 1)[1] if ":" in client else client


def _clients(clients: dict, devices: dict[str, dict]) -> str:
    return ",".join(f"{device_label(c, devices)}:{n}" for c, n in clients.items())


def _line(name: str, count: int, tag: str | None, clients: dict | None, devices: dict[str, dict], note: str = "") -> str:
    line = f"{name} {count}{note}"
    if tag:
        line += f" [{tag}]"
    if clients is not None:
        line += f" ({_clients(clients, devices)})"
    return line


def _domain_lines(domains: list[str], summary: dict, with_clients: bool) -> list[tuple[int, str]]:
    """(count, line) by count desc; numbered sibling families of 3+ hosts collapse into one pattern line"""
    families = defaultdict(list)
    for d in domains:
        families[family_key(d)].append(d)
    out = []
    for key, members in families.items():
        if len(members) < settings.family_min_size:
            for d in members:
                clients = summary["domain_clients"].get(d, {}) if with_clients else None
                out.append((summary["domain_counts"][d], _line(d, summary["domain_counts"][d], summary["tags"].get(d), clients, summary["devices"])))
            continue
        total = sum(summary["domain_counts"][d] for d in members)
        clients = None
        if with_clients:
            clients = dict(sum((Counter(summary["domain_clients"].get(d, {})) for d in members), Counter()).most_common(settings.clients_per_domain))
        out.append((total, _line(key, total, summary["tags"].get(members[0]), clients, summary["devices"], f" ({len(members)} hosts, e.g. {members[0]})")))
    return sorted(out, key=lambda x: -x[0])


def _broken_line(candidate: dict, devices: dict[str, dict]) -> str:
    rule, list_id = candidate["rule"]
    source = "user's custom rule" if list_id == 0 else "blocklist"
    return f"{candidate['domain']} blocked {candidate['blocked']}x ({_clients(candidate['clients'], devices)}) by {rule} ({source})"


def _history_line(domain: str, entry: dict) -> str:
    parts = [f"{label} {entry[key]}x" for key, label in HISTORY_LABELS.items() if entry.get(key)]
    return f"{domain}: {', '.join(parts)}, last {entry['last']}"


def build_user_message(summary: dict, state: dict, custom_blocked: set[str], custom_allowed: set[str], other_keep: int | None = None) -> str:
    """Plain-text sections for the LLM; other_keep limits OTHER to its highest-count lines when the model rejected a longer prompt"""
    memory = state["memory"]
    history = [
        _history_line(d, e)
        for d, e in memory["domain_stats"].items()
        if not is_covered(d, custom_blocked) and not is_covered(d, custom_allowed) and not is_trusted_domain(d)
    ]
    lessons = {r["domain"]: r["lesson"] for r in memory["reflections"]}
    reverts = [lessons.get(d, f"Blocking {d} was a mistake (user reverted it)") for d in sorted(reverted_domains(state))]
    other = [line for _, line in _domain_lines(summary["other_domains"], summary, False)]
    if other_keep is not None and other_keep < len(other):
        highest_omitted = _domain_lines(summary["other_domains"], summary, False)[other_keep][0]
        other = other[:other_keep] + [f"({len(other) - other_keep} lower-count domains omitted, each with at most {highest_omitted} queries)"]
    sections = [
        ("GOAL", [f"{state['goal']['primary']}. The user reviews every recommendation; nothing is blocked automatically."]),
        (
            "NETWORK",
            [
                f"{summary['total_queries']} queries, {summary['unique_domains']} unique domains, "
                f"{summary['blocked_count']} blocked by AdGuard, {summary['span']}"
            ],
        ),
        ("REVERTS", reverts),
        ("HISTORY", history),
        ("POSSIBLY BROKEN", [_broken_line(b, summary["devices"]) for b in summary["possibly_broken"]]),
        ("SKIPPED", [line for _, line in _domain_lines(summary["skipped_domains"], summary, True)]),
        ("SUSPICIOUS", [line for _, line in _domain_lines(summary["suspicious_domains"], summary, True)]),
        ("OTHER", other),
    ]
    return "\n\n".join(f"{name}:\n" + ("\n".join(lines) or "(none)") for name, lines in sections)


def _call_llm(prompt_template: str, user_message: str, summary: dict):
    with spinner(
        [
            f"Sifting {summary['total_queries']:,} DNS queries…",
            f"Profiling {len(summary['domain_counts'])} domains…",
            "Hunting trackers and telemetry…",
            "Checking past decisions…",
            "Waiting for the AI verdict…",
        ]
    ):
        return client.chat.completions.create(
            model=settings.model,
            messages=[{"role": "system", "content": prompt_template}, {"role": "user", "content": user_message}],
            response_format={"type": "json_object"},
        )


def analyze_with_llm(summary: dict, state: dict, custom_blocked: set[str], custom_allowed: set[str]) -> dict:
    """Analyze network activity with LLM and get decision"""
    with open(settings.prompt_file) as f:
        prompt_template = f.read()

    other_keep = None
    while True:
        user_message = build_user_message(summary, state, custom_blocked, custom_allowed, other_keep)
        prompt_size = len(prompt_template) + len(user_message)
        logger.info(f"LLM request: model={settings.model}, prompt size {prompt_size} characters ({prompt_size / 1024:.2f} KB)")
        try:
            resp = _call_llm(prompt_template, user_message, summary)
            break
        except BadRequestError as e:
            if e.code != "context_length_exceeded":
                raise
            if other_keep == 0:
                raise
            other_keep = (len(_domain_lines(summary["other_domains"], summary, False)) if other_keep is None else other_keep) // 2
            logger.warning(
                f"{settings.model} rejected the prompt as too long for its context window; retrying with the {other_keep} highest-count OTHER domains"
            )

    usage = resp.usage
    logger.info(f"LLM response: model={resp.model}, tokens in={usage.prompt_tokens} out={usage.completion_tokens} total={usage.total_tokens}")

    if not resp.choices[0].message.content:
        raise ValueError("Empty response from LLM")

    decision = json.loads(resp.choices[0].message.content)
    decision["ts"] = datetime.now().isoformat()
    return decision
