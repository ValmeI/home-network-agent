import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

import adguard_api
from adguard_api import _drop_subdomain_rules, _fetch_user_rules, block_domains_in_adguard, unblock_domain_in_adguard
from agent_state import _prune_domain_stats, reverted_domains, update_agent_state_with_decision
from cli_interface import display_recommendations, parse_selection, review_unblocks
from llm_analyzer import build_user_message, device_label
from network_analyzer import _suspicion_tag, aggregate, clean_decision, family_key, is_covered, is_junk, is_valid_parent, is_valid_pattern, summarize
from settings import settings


def raises(exc, fn):
    try:
        fn()
    except exc as e:
        return e
    raise AssertionError(f"expected {exc.__name__}")


G_STATE = {"goal": {"primary": "G"}, "memory": {"domain_stats": {}, "reflections": []}}

# fixed test values, so the checks do not depend on what is in the real config.yaml
settings.trusted_domains = ["github.com", "myhome.noip.me", "nas.example.cafe"]
settings.junk_suffixes = [".arpa", ".local", ".lan", ".internal", ".invalid", ".corp"]
settings.keep_blocked_domains = []
settings.device_names = {}
settings.router_ssh_jump = "jump-host"


assert is_covered("eu.i.posthog.com", {"posthog.com"})
assert is_covered("posthog.com", {"posthog.com"})
assert not is_covered("notposthog.com", {"posthog.com"})
assert not is_covered("posthog.com.evil.top", {"posthog.com"})

assert is_valid_parent("eu.i.posthog.com", "posthog.com", set())
assert not is_valid_parent("posthog.com", "posthog.com", set())
assert not is_valid_parent("eu.i.posthog.com", "com", set())
assert not is_valid_parent("a.notposthog.com", "posthog.com", set())
assert not is_valid_parent("eu.i.posthog.com", "posthog.com", {"posthog.com"})
assert not is_valid_parent("eu.i.posthog.com", "posthog.com", {"app.posthog.com"})

decision = {
    "domains_to_block": [
        {"domain": "eu.i.posthog.com", "confidence": 0.9, "parent_domain": "posthog.com", "parent_reason": "Product analytics vendor"},
        {"domain": "us.i.posthog.com", "confidence": 0.8, "parent_domain": "posthog.com", "parent_reason": "Product analytics vendor"},
        {"domain": "d1.cloudfront.net", "confidence": 0.7, "parent_domain": "d1.cloudfront.net"},
        {"domain": "ads.already.com", "confidence": 0.9},
    ],
    "domains_to_watch": [{"domain": "x.already.com", "confidence": 0.5}],
    "explanation": {"eu.i.posthog.com": "PostHog ingest", "us.i.posthog.com": "PostHog ingest", "d1.cloudfront.net": "Tracking pixel host"},
}
present0 = {"eu.i.posthog.com", "us.i.posthog.com", "d1.cloudfront.net", "ads.already.com"}
decision = clean_decision(decision, {"already.com"}, set(), present0, present0, set(), [])
assert [d["domain"] for d in decision["domains_to_block"]] == ["eu.i.posthog.com", "us.i.posthog.com", "d1.cloudfront.net"]
assert decision["domains_to_watch"] == []
assert "parent_domain" not in decision["domains_to_block"][2]

indexed = display_recommendations(decision, {})
assert indexed[1]["action"] == "parent" and indexed[1]["domain"] == "posthog.com"
assert [s["domain"] for s in parse_selection("1s", indexed)] == ["eu.i.posthog.com", "us.i.posthog.com"]
assert [s["domain"] for s in parse_selection("1, 2", indexed)] == ["posthog.com", "d1.cloudfront.net"]
assert parse_selection("9", indexed) == []

rules = ["! keep", "||other.com^", "! 2026-01-01 10:00 | old", "||eu.i.posthog.com^", "@@||app.posthog.com^", "||notposthog.com^"]
kept, removed = _drop_subdomain_rules(rules, "posthog.com")
assert removed == ["||eu.i.posthog.com^"]
assert kept == ["! keep", "||other.com^", "@@||app.posthog.com^", "||notposthog.com^"]

trusted = settings.trusted_domains[0]
hits = {"plain.com": 9, "telemetry.foo.com": 2, "skipped.com": 1, f"x.{trusted}": 50, "ads.already.com": 5, "ok.allowed.com": 4, "llm-allowed.com": 3}
now = datetime.now().astimezone()


def ts(minutes_ago: int) -> str:
    return (now - timedelta(minutes=minutes_ago)).isoformat(timespec="microseconds")[:-6] + "123" + now.isoformat()[-6:]


rows = [{"question": {"name": d}, "client_info": {"name": "nas"}} for d, n in hits.items() for _ in range(n)]
rows += [{"question": {"name": d}, "client": "192.168.50.77"} for d in ("local", "1.0.168.192.in-addr.arpa", "github.office.corp", "printer.lan", "rt-ax88u")]
rows += [{"question": {"name": "ads.filtered.com"}, "reason": "FilteredBlackList"}]
for i, row in enumerate(rows):
    row["time"] = ts(100 + i)
too_old = {"question": {"name": "ancient.com"}, "client": "x", "time": ts(60 * 24 * (settings.querylog_window_days + 1))}
pages = [rows[:40], rows[40:] + [too_old], []]
cursors = []


def fake_get(url, params, **kwargs):
    cursors.append(params.get("older_than"))
    page = pages[len(cursors) - 1]
    return mock.Mock(json=mock.Mock(return_value={"data": page, "oldest": f"t{len(cursors) - 1}" if page else ""}))


cache_file = Path(tempfile.mkdtemp()) / "querylog_cache.json"
with mock.patch.object(settings, "querylog_cache_file", str(cache_file)):
    with mock.patch.object(adguard_api.requests, "get", fake_get):
        agg = adguard_api.fetch_adguard_logs()
    assert cursors == [None, "t0"], cursors
    assert agg["total"] == len(rows) and agg["blocked"] == 1 and agg["counts"]["plain.com"] == 9
    assert agg["counts"] == aggregate(rows)["counts"] and "ancient.com" not in agg["counts"]
    assert cache_file.exists()

    new_rows = [
        {"question": {"name": "fresh.com"}, "client": "y", "time": ts(5)},
        {"question": {"name": "plain.com"}, "client_info": {"name": "nas"}, "time": ts(6)},
    ]
    pages, cursors = [new_rows + rows[:3]], []
    with mock.patch.object(adguard_api.requests, "get", fake_get):
        agg2 = adguard_api.fetch_adguard_logs()
    assert cursors == [None], cursors
    assert agg2["total"] == len(rows) + 2 and agg2["counts"]["plain.com"] == 10 and agg2["counts"]["fresh.com"] == 1
    assert agg2["clients"]["plain.com"]["nas"] == 10
summary = summarize(agg, {"already.com"}, {"allowed.com"}, {"skipped.com"})
summary["devices"] = {}
assert list(summary["domain_counts"]) == ["plain.com", "llm-allowed.com", "telemetry.foo.com", "skipped.com"]
assert summary["skipped_domains"] == ["skipped.com"]
assert summary["suspicious_domains"] == ["telemetry.foo.com"]
assert summary["other_domains"] == ["plain.com", "llm-allowed.com"]
assert summary["domain_clients"]["plain.com"] == {"nas": 9} and f"x.{trusted}" not in summary["domain_clients"]
assert summary["blocked_count"] == 1
assert all(is_junk(d) for d in ("local", "rt-ax88u", "1.0.168.192.in-addr.arpa", "github.office.corp", "printer.lan", "x.home.arpa"))
assert not is_junk("corp-auth.example.ee")

state = {"goal": {"primary": "Goal"}, "memory": {"history": [], "stats": {"total_decisions": 0, "reverts": 0}, "domain_stats": {}, "reflections": []}}
llm = {
    "domains_to_block": [{"domain": "skipped.com", "confidence": 0.85}],
    "domains_to_watch": [{"domain": "plain.com", "confidence": 0.5}],
    "domains_to_allow": ["llm-allowed.com"],
}
state = update_agent_state_with_decision(state, summary, llm, [])
assert state["memory"]["domain_stats"]["skipped.com"]["skipped"] == 1
assert "llm-allowed.com" not in state["memory"]["domain_stats"]
state = update_agent_state_with_decision(state, summary, llm, ["skipped.com"])
assert state["memory"]["domain_stats"]["skipped.com"] == {
    "recommended": 2,
    "skipped": 1,
    "blocked": 1,
    "last": state["memory"]["domain_stats"]["skipped.com"]["last"],
}
state["memory"]["domain_stats"]["sub.already.com"] = {"blocked": 1, "last": "2099-01-01"}

message = build_user_message(summary, state, {"already.com"}, {"allowed.com"})
assert message.index("skipped.com 1") < message.index("telemetry.foo.com 2 [kw:telemetry] (nas:2)") < message.index("plain.com 9\n")
assert "skipped.com: recommended block 2x, user skipped 1x, user blocked 1x, last " in message and "conf" not in message
assert "sub.already.com" not in message and f"x.{trusted}" not in message
assert (
    clean_decision({"domains_to_block": [{"domain": f"x.{trusted}"}], "domains_to_watch": []}, set(), set(), {f"x.{trusted}"}, {f"x.{trusted}"}, set(), [])[
        "domains_to_block"
    ]
    == []
)

present = {"a.sentry.io", "plain.com", "onedscolprdcus07.centralus.cloudapp.azure.com"}
d = clean_decision(
    {
        "domains_to_block": [
            {"domain": "browser.sentry-cdn.com", "confidence": 0.84, "parent_domain": "sentry-cdn.com"},
            {"domain": "sentry.io", "confidence": 0.9},
            {"domain": "onedscolprdcus*.centralus.cloudapp.azure.com", "confidence": 0.9},
            {"domain": "onedscolprdcus07.centralus.cloudapp.azure.com", "confidence": 0.9},
        ],
        "domains_to_watch": [{"domain": "js.klevu.com", "confidence": 0.5}, {"domain": "plain.com", "confidence": 0.5}],
    },
    set(),
    set(),
    present,
    present,
    set(),
    [],
)
assert [x["domain"] for x in d["domains_to_block"]] == ["onedscolprdcus*.centralus.cloudapp.azure.com", "onedscolprdcus07.centralus.cloudapp.azure.com"]
assert [x["domain"] for x in d["domains_to_watch"]] == ["plain.com"]

assert family_key("onedscolprdwus62.westus.cloudapp.azure.com") == family_key("onedscolprdwus7.westus.cloudapp.azure.com")
assert family_key("ipv4-c001-tll010-teliaee-isp.1.oca.nflxvideo.net") == "ipv*-c*-tll*-teliaee-isp.*.oca.nflxvideo.net"
assert family_key("02c5a3dab98f521b.vercel-dns-016.com") == "*.vercel-dns-*.com"
fam = {f"onedscolprdwus{n}.westus.cloudapp.azure.com": n for n in (60, 61, 62)} | {"tel.foo.com": 5, "tel2.foo.com": 1, "tel3.foo.com": 1}
fam_summary = {
    "total_queries": 0, "unique_domains": 0, "blocked_count": 0, "span": "",
    "domain_counts": fam, "skipped_domains": [], "suspicious_domains": [], "other_domains": list(fam), "tags": {}, "domain_clients": {}, "possibly_broken": [], "devices": {},
}  # fmt: skip
fam_msg = build_user_message(fam_summary, G_STATE, set(), set())
assert "onedscolprdwus*.westus.cloudapp.azure.com 183 (3 hosts, e.g. onedscolprdwus60.westus.cloudapp.azure.com)" in fam_msg
assert "tel.foo.com 5" in fam_msg and "tel*.foo.com" not in fam_msg
cut_msg = build_user_message(fam_summary, G_STATE, set(), set(), other_keep=2)
assert "tel3.foo.com" not in cut_msg and "onedscolprdwus*" in cut_msg and "lower-count domains omitted" in cut_msg

with mock.patch.dict(settings.device_names, {"192.168.50.13": "nas"}):
    devs = {"192.168.50.216": {"label": "lg-webos-tv"}, "192.168.50.13": {"label": "router-name"}}
    assert [device_label(c, devs) for c in ("192.168.50.13", "192.168.50.216", "192.168.50.24", "fe80::1:abcd", "localhost")] == [
        "nas", "lg-webos-tv", "dev24", "devabcd", "localhost",
    ]  # fmt: skip

azure = {"onedscolprdwus62.westus.cloudapp.azure.com", "onedscolprdcus07.centralus.cloudapp.azure.com", "good.cloudapp.azure.com"}
assert is_covered("onedscolprdwus62.westus.cloudapp.azure.com", {"onedscolprd*.cloudapp.azure.com"})
assert not is_covered("good.cloudapp.azure.com", {"onedscolprd*.cloudapp.azure.com"})
assert is_valid_pattern("onedscolprd*.cloudapp.azure.com", azure, set())
assert not is_valid_pattern("*.cloudapp.azure.com", azure, set())
assert not is_valid_pattern("onedscolprd*.com", azure, set())
assert not is_valid_pattern("onedscolprd*.cloudapp.azure.com", azure, {"onedscolprdwus62.westus.cloudapp.azure.com"})
assert not is_valid_pattern("nothere*.cloudapp.azure.com", azure, set())
d = clean_decision(
    {"domains_to_block": [{"domain": "onedscolprd*.cloudapp.azure.com"}, {"domain": "*.cloudapp.azure.com"}], "domains_to_watch": []},
    set(),
    set(),
    azure,
    azure,
    set(),
    [],
)
assert [x["domain"] for x in d["domains_to_block"]] == ["onedscolprd*.cloudapp.azure.com"]
kept, removed = _drop_subdomain_rules(
    ["! 2026-01-01 10:00 | c", "||onedscolprdwus62.westus.cloudapp.azure.com^", "||good.cloudapp.azure.com^"], "onedscolprd*.cloudapp.azure.com"
)
assert kept == ["||good.cloudapp.azure.com^"] and removed == ["||onedscolprdwus62.westus.cloudapp.azure.com^"]
assert not is_valid_parent("static.klaviyo.com", "klaviyo.com", set())
for bad_parent in ("co.uk", "com.ee", "cloudapp.azure.com", "azure.com", "noip.me", "example.cafe"):
    assert not is_valid_parent(f"x.{bad_parent}", bad_parent, set()), bad_parent
assert is_valid_parent("x.posthog.co.uk", "posthog.co.uk", set())

assert _suspicion_tag("downloads.claude.ai") == "" and _suspicion_tag("www.threads.com") == ""
assert _suspicion_tag("ads.example.com") == "kw:ads" and _suspicion_tag("telemetry.qdrant.io") == "kw:telemetry"
assert _suspicion_tag("0a1b2c3d4e5f60718293a4b5c6d7e8f9.plex.direct") != "dga"
assert _suspicion_tag("configdl-production-production.trafficmanager.net") != "dga"

veto_present = {
    "checkoutanalytics-live.adyen.com", "static.klaviyo.com", "ocsp.digicert.com", "pay.google.com", "update.example.com",
    "cell-1.eu-west-1.prod.telemetry.console.api.aws", "x.reverted-parent.com", "tracker.realtracker.com",
    "telemetry.cell-0.us-east-1.prod.tangerinebox.console.aws.a2z.com",
}  # fmt: skip
d = clean_decision(
    {"domains_to_block": [{"domain": x} for x in sorted(veto_present)] + [{"domain": "reverted-parent.com"}], "domains_to_watch": []},
    set(), set(), veto_present, veto_present, {"cell-0.eu-west-1.prod.telemetry.console.api.aws", "x.reverted-parent.com", "telemetry.cell-0.eu-west-1.prod.tangerinebox.console.aws.a2z.com"}, [],
)  # fmt: skip
assert [x["domain"] for x in d["domains_to_block"]] == ["tracker.realtracker.com"], d["domains_to_block"]
d = clean_decision(
    {"domains_to_block": [{"domain": "a.posthog.com", "parent_domain": "posthog.com"}], "domains_to_watch": []},
    set(), set(), {"a.posthog.com"}, {"a.posthog.com"}, {"b.posthog.com"}, [],
)  # fmt: skip
assert d["domains_to_block"] == [{"domain": "a.posthog.com"}]

with mock.patch.object(settings, "trusted_domains", ["myhome.noip.me"]):
    assert not is_valid_pattern("myh*.noip.me", {"myhome2.noip.me"}, set())
    assert not is_valid_pattern("myh*.noip.me", {"myhome.noip.me", "myhx.noip.me"}, set())
assert not is_valid_pattern("www*.co.uk", {"www1.co.uk"}, set())
assert not is_valid_pattern("static*.klaviyo.com", {"static1.klaviyo.com"}, set())
assert not is_valid_pattern("tele*.example.com", {"tele1.example.com", "tele2.example.com"}, {"tele2.example.com"})

old_state = {"memory": {"domain_stats": {"old.com": {"last": "2000-01-01"}, "oops.com": {"last": "2000-01-01", "reverted": 1}}, "reflections": []}}
_prune_domain_stats(old_state)
assert reverted_domains(old_state) == {"oops.com"} and "old.com" not in old_state["memory"]["domain_stats"]

store = {"rules": ["# section", "||keep.com^", "! My section", "! 2026-01-01 10:00 | agent comment", "||a.vendor.com^", "@@||allowed.com^"]}
posted = []


def rules_get(url, **kwargs):
    return mock.Mock(json=mock.Mock(return_value={"user_rules": list(store["rules"])}))


def rules_post(url, json, **kwargs):
    posted.append(json["rules"])
    store["rules"] = json["rules"]
    return mock.Mock()


backup_dir = Path(tempfile.mkdtemp())
with (
    mock.patch.object(adguard_api.requests, "get", rules_get),
    mock.patch.object(adguard_api.requests, "post", rules_post),
    mock.patch.object(settings, "rules_backup_dir", str(backup_dir)),
    mock.patch.object(settings, "rules_backup_keep", 2),
):
    assert block_domains_in_adguard([("vendor.com", "tracking vendor"), ("x.vendor.com", "covered"), ("other.com", "ads")]) == ["vendor.com", "other.com"]
    assert len(posted) == 1, "a batch of blocks must be one write"
    assert "||a.vendor.com^" not in store["rules"] and "||vendor.com^" in store["rules"] and "||other.com^" in store["rules"]
    assert "! My section" in store["rules"] and "! 2026-01-01 10:00 | agent comment" not in store["rules"]
    assert any("replaces: ||a.vendor.com^" in r for r in store["rules"])
    assert unblock_domain_in_adguard("vendor.com")
    assert "||vendor.com^" not in store["rules"] and "||a.vendor.com^" in store["rules"] and "@@||allowed.com^" in store["rules"]
    assert block_domains_in_adguard([("onedscolprd*.cloudapp.azure.com", "telemetry")])
    assert unblock_domain_in_adguard("onedscolprdwus1.westus.cloudapp.azure.com")
    assert store["rules"][-1] == "@@||onedscolprdwus1.westus.cloudapp.azure.com^" and "||onedscolprd*.cloudapp.azure.com^" in store["rules"]
    assert unblock_domain_in_adguard("never-blocked.com") is False
    n_posts = len(posted)
    assert unblock_domain_in_adguard("onedscolprdwus1.westus.cloudapp.azure.com")
    assert len(posted) == n_posts and store["rules"].count("@@||onedscolprdwus1.westus.cloudapp.azure.com^") == 1, "no duplicate allow rule"
    store["rules"] += ["||wide.com^", "||a.wide.com^"]
    assert unblock_domain_in_adguard("a.wide.com")
    assert "||a.wide.com^" not in store["rules"] and store["rules"][-1] == "@@||a.wide.com^", "still covered by ||wide.com^, needs an allow rule"
    n_posts = len(posted)
    raises(RuntimeError, lambda: adguard_api._save_rules(store["rules"], [r for r in store["rules"] if not r.startswith("@@")]))
    assert len(posted) == n_posts
    assert len(list(backup_dir.glob("user_rules_*.json"))) == 2
    with mock.patch.object(adguard_api.requests, "post", side_effect=adguard_api.requests.HTTPError("500")):
        raises(adguard_api.requests.HTTPError, lambda: block_domains_in_adguard([("fail.com", "x")]))

with mock.patch.object(adguard_api.requests, "get", lambda url, **kw: mock.Mock(json=mock.Mock(return_value={}))):
    raises(KeyError, lambda: _fetch_user_rules())

import httpx  # noqa: E402
import llm_analyzer  # noqa: E402
from openai import BadRequestError  # noqa: E402

limit = len(fam_msg) - 5
sent = []


def fake_create(model, messages, response_format):
    sent.append(len(messages[1]["content"]))
    if len(messages[0]["content"]) + len(messages[1]["content"]) > limit:
        raise BadRequestError("too long", response=httpx.Response(400, request=httpx.Request("POST", "http://x")), body={"code": "context_length_exceeded"})
    usage = mock.Mock(prompt_tokens=1, completion_tokens=1, total_tokens=2)
    return mock.Mock(usage=usage, model="m", choices=[mock.Mock(message=mock.Mock(content='{"decision": "ALLOW"}'))])


with mock.patch.object(llm_analyzer.client.chat.completions, "create", fake_create), mock.patch("builtins.open", mock.mock_open(read_data="")):
    assert llm_analyzer.analyze_with_llm(fam_summary, G_STATE, set(), set())["decision"] == "ALLOW"
assert len(sent) > 1 and sent[-1] < sent[0] and sent[-1] <= limit, sent


def other_error(model, messages, response_format):
    raise BadRequestError("bad", response=httpx.Response(400, request=httpx.Request("POST", "http://x")), body={"code": "invalid_value"})


with mock.patch.object(llm_analyzer.client.chat.completions, "create", other_error), mock.patch("builtins.open", mock.mock_open(read_data="")):
    raises(BadRequestError, lambda: llm_analyzer.analyze_with_llm(fam_summary, G_STATE, set(), set()))

blocked_rows = [
    {"question": {"name": "lg-tv-2019.prod.partner.netflix.net"}, "client": "192.168.50.216", "reason": "FilteredBlackList",
     "rules": [{"text": "||partner.netflix.net^", "filter_list_id": 0}]}
] * 5 + [
    {"question": {"name": "logs.netflix.com"}, "client": "192.168.50.216", "reason": "FilteredBlackList", "rules": [{"text": "||logs.netflix.com^", "filter_list_id": 1}]}
] * 2  # fmt: skip
storm_agg = aggregate(blocked_rows)
storm_agg["counts"]["plain.com"] = 1
with mock.patch.object(settings, "retry_storm_min_blocked", 3), mock.patch.object(settings, "keep_blocked_domains", []):
    storm_summary = summarize(storm_agg, set(), set(), set())
storm_summary["devices"] = {}
with mock.patch.object(settings, "retry_storm_min_blocked", 3), mock.patch.object(settings, "keep_blocked_domains", ["partner.netflix.net"]):
    assert summarize(storm_agg, set(), set(), set())["possibly_broken"] == []
assert storm_summary["possibly_broken"] == [
    {"domain": "lg-tv-2019.prod.partner.netflix.net", "blocked": 5, "clients": {"192.168.50.216": 5}, "rule": ["||partner.netflix.net^", 0]}
]
with mock.patch.dict(settings.device_names, {"192.168.50.216": "lg-tv"}):
    storm_msg = build_user_message(storm_summary, G_STATE, set(), set())
assert "lg-tv-2019.prod.partner.netflix.net blocked 5x (lg-tv:5) by ||partner.netflix.net^ (user's custom rule)" in storm_msg
d = clean_decision(
    {"domains_to_block": [], "domains_to_watch": [], "domains_to_unblock": [{"domain": "lg-tv-2019.prod.partner.netflix.net"}, {"domain": "logs.netflix.com"}]},
    set(), set(), set(), set(), set(), storm_summary["possibly_broken"],
)  # fmt: skip
assert d["domains_to_unblock"] == [{"domain": "lg-tv-2019.prod.partner.netflix.net"}]

store["rules"] = ["||partner.netflix.net^", "@@||allowed.com^"]
with (
    mock.patch.object(adguard_api.requests, "get", rules_get),
    mock.patch.object(adguard_api.requests, "post", rules_post),
    mock.patch.object(settings, "rules_backup_dir", str(backup_dir)),
):
    assert unblock_domain_in_adguard("lg-tv-2019.prod.partner.netflix.net")
    assert store["rules"][-1] == "@@||lg-tv-2019.prod.partner.netflix.net^" and "||partner.netflix.net^" in store["rules"]
    assert unblock_domain_in_adguard("listed-only.com") is False
    assert unblock_domain_in_adguard("listed-only.com", blocked_by_list=True) and store["rules"][-1] == "@@||listed-only.com^"

with mock.patch("builtins.input", side_effect=["1"]):
    assert review_unblocks(d, storm_summary["possibly_broken"]) == [{"domain": "lg-tv-2019.prod.partner.netflix.net"}]
with mock.patch("builtins.input", side_effect=[""]):
    assert review_unblocks(d, storm_summary["possibly_broken"]) == []

import router  # noqa: E402

router_output = (
    "1760000000 aa:bb:cc:00:00:01 192.168.50.216 LGwebOSTV 01:aa:bb\n"
    "1760000000 aa:bb:cc:00:00:02 192.168.50.24 * 01:aa:bb\n"
    "1760000000 aa:bb:cc:00:00:03 192.168.50.30 * *\n"
    "@@\n"
    "<Living room TV>AA:BB:CC:00:00:01>0>4>><Annas iPhone>AA:BB:CC:00:00:02>0>10>>\n"
    "@@\n"
    "IP address       HW type     Flags       HW address            Mask     Device\n"
    "192.168.50.13    0x1         0x2         aa:bb:cc:00:00:13     *        br0\n"
    "192.168.50.99    0x1         0x0         00:00:00:00:00:00     *        br0\n"
)
assert router.parse_router_output(router_output) == {"192.168.50.216": {"label": "living-room-tv"}, "192.168.50.24": {"label": "annas-iphone"}}
with mock.patch.object(router.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=router_output, stderr="")) as run:
    assert router.get_router_devices()["192.168.50.216"] == {"label": "living-room-tv"}
args = run.call_args.args[0]
assert args[-2] == settings.router_ssh_jump and router.COMMAND in args[-1] and "BatchMode=yes" in args[-1]
with (
    mock.patch.object(settings, "router_ssh_jump", ""),
    mock.patch.object(router.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=router_output, stderr="")) as run,
):
    router.get_router_devices()
assert run.call_args.args[0][-2:] == [settings.router_ssh_host, router.COMMAND]
with mock.patch.object(router.subprocess, "run", return_value=mock.Mock(returncode=255, stdout="", stderr="Permission denied (publickey)")):
    assert "Permission denied" in str(raises(RuntimeError, lambda: router.get_router_devices()))

assert summarize(storm_agg, set(), {"partner.netflix.net"}, set())["possibly_broken"] == [], "already allowed domains are not possibly broken"
with mock.patch("builtins.input", side_effect=["1 1"]):
    assert review_unblocks(d, storm_summary["possibly_broken"]) == [{"domain": "lg-tv-2019.prod.partner.netflix.net"}]

assert "each with at most 183 queries" in build_user_message(fam_summary, G_STATE, set(), set(), other_keep=0)

parent_present = {"x.amazonaws.com", "a.cloudapp.azure.com", "foo.com", "eu.i.posthog.com", "us.i.posthog.com", "login.shop.com", "ads.shop.com"}
parent_items = ["amazonaws.com", "cloudapp.azure.com", "com", "posthog.com", "shop.com", "ads.shop.com", "eu.i.posthog.com", "eu.i.posthog.com"]
d = clean_decision({"domains_to_block": [{"domain": x} for x in parent_items], "domains_to_watch": []}, set(), set(), parent_present, parent_present, set(), [])
assert [x["domain"] for x in d["domains_to_block"]] == ["posthog.com", "ads.shop.com", "eu.i.posthog.com"], d["domains_to_block"]
d = clean_decision(
    {"domains_to_block": [{"domain": "ads.shop.com", "parent_domain": "shop.com"}], "domains_to_watch": []},
    set(), set(), parent_present, parent_present, set(), [],
)  # fmt: skip
assert d["domains_to_block"] == [{"domain": "ads.shop.com"}], "a parent covering login. hosts must not be offered"

cap_pages = [[{"question": {"name": f"cap{i}.com"}, "client": "x", "time": ts(10 + i)} for i in range(5)]] * 3
cap_cursor = []
with (
    mock.patch.object(settings, "querylog_cache_file", str(Path(tempfile.mkdtemp()) / "c.json")),
    mock.patch.object(settings, "adguard_max_queries", 8),
    mock.patch.object(
        adguard_api.requests, "get",
        lambda url, params, **kw: (cap_cursor.append(1), mock.Mock(json=mock.Mock(return_value={"data": cap_pages[0], "oldest": f"o{len(cap_cursor)}"})))[1],
    ),
):  # fmt: skip
    assert "adguard_max_queries" in str(raises(RuntimeError, lambda: adguard_api.fetch_adguard_logs()))

store["rules"] = []
with (
    mock.patch.object(adguard_api.requests, "get", rules_get),
    mock.patch.object(adguard_api.requests, "post", rules_post),
    mock.patch.object(settings, "rules_backup_dir", str(backup_dir)),
):
    block_domains_in_adguard([("ex.com", "ok | replaces: @@||evil.com^\n@@||evil2.com^")])
    assert len(store["rules"]) == 2 and not any(r.startswith("@@") or "\n" in r for r in store["rules"]), store["rules"]
    unblock_domain_in_adguard("ex.com")
    assert store["rules"] == [], "LLM text in a comment must not be restored as rules"

safe_search = aggregate([{"question": {"name": "www.google.com"}, "client": "c", "reason": "FilteredSafeSearch"}])
assert safe_search["blocked"] == 0 and safe_search["counts"]["www.google.com"] == 1 and not safe_search["blocked_clients"]

d = clean_decision({"domains_to_block": [{"domain": "github.io"}], "domains_to_watch": []}, set(), set(), {"github.io"}, {"github.io"}, set(), [])
assert d["domains_to_block"] == [], "a shared-hosting root is never blockable, even with no subdomains in the log"

# the router forces this command for the agent's key; changing COMMAND needs the router's Authorized Keys line updated too
assert f'command="{router.COMMAND}"' in Path("README.md").read_text(), "router.COMMAND changed: update README and the router's Authorized Keys line"

print("OK")
