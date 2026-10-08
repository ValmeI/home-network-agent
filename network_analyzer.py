import math
import re
from fnmatch import fnmatchcase
from collections import Counter, defaultdict

from loguru import logger

from settings import settings


def _matches(domain: str, rule: str) -> bool:
    if "*" in rule:
        return fnmatchcase(domain, rule) or fnmatchcase(domain, "*." + rule)
    return domain == rule or domain.endswith("." + rule)


def is_covered(domain: str, domains) -> bool:
    """Exact, subdomain or AdGuard-style wildcard match - substring matching would let github.com.evil.top spoof a match"""
    return any(_matches(domain, d) for d in domains)


def is_valid_pattern(pattern: str, queried: set[str], custom_allowed: set[str]) -> bool:
    """Safe wildcard: hits the log and touches no trusted, allowed or protected domain - checked against
    those lists directly too, since the pattern also covers hosts not seen yet"""
    head = pattern.partition("*")[0]
    tail = _wildcard_tail(pattern)
    protected = [*settings.trusted_domains, *custom_allowed, *settings.protected_vendor_domains]
    hits = [d for d in queried if _matches(d, pattern)]
    return (
        len(head.split(".")[0]) >= 3
        and tail.count(".") >= 1
        and not _is_public_suffix(tail)
        and bool(hits)
        and not any(is_covered(d, protected) for d in hits)
        and not any(_matches(p, pattern) or is_covered(tail, {p}) for p in protected)
    )


def _wildcard_tail(pattern: str) -> str:
    return pattern.rsplit("*", 1)[-1].lstrip(".")


def is_trusted_domain(domain: str) -> bool:
    return is_covered(domain, settings.trusted_domains)


# second-level labels of country public suffixes (co.uk, com.ee, org.au...) - a parent there blocks a whole country's sites
_PUBLIC_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "edu", "ac"}


def _is_public_suffix(parent: str) -> bool:
    labels = parent.split(".")
    return len(labels) == 2 and labels[0] in _PUBLIC_SECOND_LEVEL and len(labels[1]) == 2


def _clashes(parent: str, domains) -> bool:
    """Parent falls under one of the domains, or would cover one of them"""
    return is_covered(parent, domains) or any(is_covered(d, {parent}) for d in domains)


def is_valid_parent(domain: str, parent: str, custom_allowed: set[str]) -> bool:
    """Parent must be a real parent, not a public suffix, and must neither fall under nor contain a trusted, protected or allowed domain"""
    return (
        parent.count(".") >= 1
        and "*" not in parent
        and domain.endswith("." + parent)
        and not _is_public_suffix(parent)
        and not _clashes(parent, [*settings.trusted_domains, *settings.no_parent_block_domains, *settings.protected_vendor_domains, *custom_allowed])
    )


def _is_shared_root(domain: str) -> bool:
    """Bare TLD, country public suffix, or a shared-hosting parent itself (github.io, amazonaws.com) - never blockable as a whole"""
    return "." not in domain or _is_public_suffix(domain) or any(is_covered(n, {domain}) for n in settings.no_parent_block_domains)


def _hosts_under(parent: str, queried: set[str]) -> list[str]:
    return [q for q in queried if q.endswith("." + parent)]


def _parent_ok(parent: str, queried: set[str], blocked_safe: set[str]) -> bool:
    """A domain that covers other queried hosts is a whole-domain block: it needs the full parent check,
    and none of the hosts it would cover may carry a never-block keyword (login., pay., auth.)"""
    hosts = _hosts_under(parent, queried)
    return bool(hosts) and is_valid_parent(hosts[0], parent, blocked_safe) and not any(_starts_part(h, settings.never_block_keywords) for h in hosts)


def _has_suspicious_tld(domain: str) -> bool:
    return any(domain.endswith(tld) for tld in settings.suspicious_tlds)


def _looks_dga(domain: str) -> bool:
    """Long high-entropy label = likely machine-generated (DGA) domain"""
    label = max(re.split(r"[.-]", domain), key=len)
    if len(label) < settings.dga_min_label_len or re.fullmatch(r"[0-9a-f-]+", label):
        return False
    probs = [count / len(label) for count in Counter(label).values()]
    entropy = -sum(p * math.log2(p) for p in probs)
    return entropy > settings.dga_entropy_threshold


def _should_filter_out(domain: str) -> bool:
    for keyword in settings.filter_out_keywords:
        if keyword in domain.lower():
            return True
    return False


def _filter_domains(items: list[dict], custom_blocked: set[str], custom_allowed: set[str]) -> list[dict]:
    return [
        item
        for item in items
        if item.get("domain")
        and not is_covered(item["domain"], custom_blocked)
        and not is_covered(item["domain"], custom_allowed)
        and not is_trusted_domain(item["domain"].lower())
        and not _should_filter_out(item["domain"])
    ]


def aggregate(queries: list[dict], agg: dict | None = None) -> dict:
    """Fold one querylog page into running per-domain counts, so a week of raw rows never sits in memory"""
    agg = agg or {"total": 0, "blocked": 0, "counts": Counter(), "clients": defaultdict(Counter), "blocked_clients": defaultdict(Counter), "blocked_rules": {}}
    for q in queries:
        agg["total"] += 1
        domain = q.get("question", {}).get("name", "")
        client = q.get("client_info", {}).get("name") or q.get("client", "unknown")
        # FilteredSafeSearch is a rewrite to the safe-search address, not a block
        if q.get("reason", "").startswith("Filtered") and q["reason"] != "FilteredSafeSearch":
            agg["blocked"] += 1
            if domain:
                agg["blocked_clients"][domain][client] += 1
                rule = (q.get("rules") or [{}])[0]
                agg["blocked_rules"].setdefault(domain, [rule.get("text", "?"), rule.get("filter_list_id", "?")])
            continue
        if not domain:
            continue
        agg["clients"][domain][client] += 1
        if not _should_filter_out(domain):
            agg["counts"][domain] += 1
    return agg


def is_junk(domain: str) -> bool:
    """Reverse-DNS, bare hostnames and LAN/search-domain names carry no signal"""
    return "." not in domain.strip(".") or domain.endswith(tuple(settings.junk_suffixes))


def family_key(domain: str) -> str:
    """Numbered/hex siblings (onedscolprdwus62..., ipv4-c001-...) share one key"""
    return re.sub(r"\d+", "*", re.sub(rf"(?<![^.-])[0-9a-f]{{{settings.family_hex_min_len},}}(?![^.-])", "*", domain))


def _name_parts(domain: str) -> list[str]:
    return re.split(r"[.*-]", domain.lower())


def _starts_part(domain: str, keywords) -> str | None:
    """First keyword that starts a name part - whole-part matching keeps 'ads' out of 'downloads'"""
    return next((k for k in keywords if any(part.startswith(k) for part in _name_parts(domain))), None)


def _suspicion_tag(domain: str) -> str:
    lower = domain.lower()
    keyword = _starts_part(lower, settings.suspicious_keywords)
    if keyword:
        return f"kw:{keyword}"
    if _has_suspicious_tld(lower):
        return "tld"
    return "dga" if _looks_dga(lower) else ""


def summarize(agg: dict, custom_blocked: set[str], custom_allowed: set[str], skipped: set[str]) -> dict:
    """Review lists hold every non-junk, non-trusted domain not covered by AdGuard rules, ordered skipped > suspicious > rest"""
    if not agg["total"]:
        return {"error": "No queries found"}

    counts = agg["counts"]
    review = [
        d
        for d, _ in counts.most_common()
        if not is_junk(d) and not is_trusted_domain(d.lower()) and not is_covered(d, custom_blocked) and not is_covered(d, custom_allowed)
    ]
    tags = {d: tag for d in review if (tag := _suspicion_tag(d))}

    return {
        "total_queries": agg["total"],
        "unique_domains": len(counts),
        "blocked_count": agg["blocked"],
        "span": f"{agg.get('oldest', '?')[:16]} to {agg.get('newest', '?')[:16]}",
        "domain_counts": {d: counts[d] for d in review},
        "skipped_domains": [d for d in review if d in skipped],
        "suspicious_domains": [d for d in review if d in tags and d not in skipped],
        "other_domains": [d for d in review if d not in tags and d not in skipped],
        "tags": tags,
        "domain_clients": {d: dict(agg["clients"][d].most_common(settings.clients_per_domain)) for d in review},
        "possibly_broken": sorted(
            (
                {"domain": d, "blocked": sum(c.values()), "clients": dict(c.most_common(settings.clients_per_domain)), "rule": agg["blocked_rules"][d]}
                for d, c in agg["blocked_clients"].items()
                if not is_junk(d)
                and not is_covered(d, settings.keep_blocked_domains)
                and not is_covered(d, custom_allowed)
                and c.most_common(1)[0][1] >= settings.retry_storm_min_blocked
            ),
            key=lambda x: -x["blocked"],
        ),
    }


def _in_log(domain: str, present: set[str]) -> bool:
    # ponytail: linear scan for parent/wildcard entries, fine for ~50 recommendations
    return domain in present or any(_matches(p, domain) for p in present)


def _block_veto(domain: str, reverted: set[str]) -> str | None:
    """Why a block suggestion must never be offered, or None"""
    if is_covered(_wildcard_tail(domain), settings.protected_vendor_domains):
        return "protected vendor"
    keyword = _starts_part(domain, settings.never_block_keywords)
    if keyword:
        return f"never-block keyword '{keyword}'"
    for r in reverted:
        labels = r.split(".")
        root = ".".join(labels[-settings.revert_sibling_depth :]) if len(labels) > settings.revert_sibling_depth else r
        if is_covered(domain, {root}) or is_covered(r, {domain}) or family_key(domain) == family_key(r):
            return f"user reverted {r}"
    return None


def clean_decision(
    decision: dict, custom_blocked: set[str], custom_allowed: set[str], present: set[str], queried: set[str], reverted: set[str], possibly_broken: list[dict]
) -> dict:
    """Drop LLM suggestions that are already covered, absent from the log or unsafe; each drop is logged"""
    for key in ("domains_to_block", "domains_to_watch"):
        raw = decision.get(key, [])
        bare = sum(isinstance(item, str) for item in raw)
        if bare:
            logger.info(f"LLM returned {bare} {key} entries as bare strings, normalised to dicts")
        before = [{"domain": item} if isinstance(item, str) else item for item in raw if isinstance(item, (str, dict))]
        unique = list({item.get("domain"): item for item in reversed(before)}.values())[::-1]
        decision[key] = _filter_domains(unique, custom_blocked, custom_allowed)
        if len(unique) < len(before):
            logger.info(f"Dropped {len(before) - len(unique)} duplicate {key} entries")
        if len(decision[key]) < len(unique):
            logger.info(f"Dropped {len(unique) - len(decision[key])} {key} entries already covered by AdGuard rules")
        kept, absent = [], []
        for item in decision[key]:
            domain = item["domain"]
            veto = _block_veto(domain, reverted) if key == "domains_to_block" else None
            if veto:
                logger.info(f"Dropped {domain} from {key}: {veto}")
            elif "*" in domain and not is_valid_pattern(domain, queried, custom_allowed):
                logger.info(f"Dropped wildcard {domain} from {key} (failed safety check)")
            elif key == "domains_to_block" and "*" not in domain and _is_shared_root(domain):
                logger.info(f"Dropped {domain} from {key}: it is a public suffix or shared hosting, blocking it would cut unrelated sites")
            elif (
                key == "domains_to_block" and "*" not in domain and _hosts_under(domain, queried) and not _parent_ok(domain, queried, custom_allowed | reverted)
            ):
                logger.info(f"Dropped {domain} from {key}: it would block other hosts too and failed the whole-domain safety check")
            elif not _in_log(domain, present):
                absent.append(domain)
            else:
                kept.append(item)
        if absent:
            logger.info(f"Dropped {key} entries not in the fetched query log: {', '.join(absent)}")
        decision[key] = kept
    broken = {b["domain"] for b in possibly_broken}
    unblock = decision.get("domains_to_unblock", [])
    decision["domains_to_unblock"] = [item for item in unblock if isinstance(item, dict) and item.get("domain") in broken]
    if len(decision["domains_to_unblock"]) < len(unblock):
        logger.info(f"Dropped {len(unblock) - len(decision['domains_to_unblock'])} unblock suggestions not listed as possibly broken")
    for item in decision["domains_to_block"]:
        parent = item.get("parent_domain")
        if parent and not (item["domain"].endswith("." + parent) and _parent_ok(parent, queried, custom_allowed | reverted)):
            logger.info(f"Discarded parent_domain {parent} for {item['domain']} (failed safety check)")
            item.pop("parent_domain")
            item.pop("parent_reason", None)
    return decision
