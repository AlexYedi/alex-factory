#!/usr/bin/env python3
"""Turn the model's output into a merge decision, deterministically.

Two steps, both fail closed:
  --sanitize (review job) reduces the CLI envelope to schema-checked fields whose
    text is verified against the diff, so no model prose reaches an artifact.
  --decide (decide job) re-verifies that and decides PASS, HOLD, BLOCK or SKIP.

A PASS needs a positive reviewed:true. Silence is never approval, because an
injected "say nothing" must not read the same as a clean review.

When the review cannot speak (fork, too large, expired token), a person decides
and the App never approves. All T2 stays red until a code owner has approved this
exact commit: the gate cannot see what CODEOWNERS covers, so it never assumes it.

A model BLOCK is sticky per diff, so an empty commit can't re-roll it.
"""
import argparse
import json
import os
import re
import sys
import tempfile

from minischema import validate
from risk_tier import DiffError, _flatten, _read_json, classify, parse_diff, sticky_marker

MIN_QUOTE_CHARS = 8
USAGE_KEYS = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
DEFAULT_SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "verdict.schema.json")
MAX_LISTED = 20
COMMENT_MARKER = "<!-- factory-gate -->"
NOTES = {
    "owner_approval_required": "A code owner must approve this commit. The App never approves T2.",
    "sticky_block": "A review already blocked this exact diff. Change the code to get a new review.",
    "gate_data_missing": "The gate's saved data has expired. Re-run all jobs or push a commit.",
    "classify_failed": "The classify job failed. Check its log, then re-run all jobs.",
    "app_approval_dismissed": "The App's approval of this commit was dismissed, so it won't approve it again.",
}


def _squash(text):
    return " ".join(text.split())


def diff_index(stripped):
    """Map each changed path to its (line number, text) pairs."""
    index = {}
    try:
        changes = parse_diff(stripped or "")
    except DiffError:
        return {}
    for change in changes:
        path = change["new"] or change["old"]
        index[path] = [(new_no or old_no, _squash(text)) for _, old_no, new_no, text in change["lines"]]
    return index


def locate(finding, index):
    """Return the true line for a finding's quote, or None if it is not in the diff."""
    quote = finding.get("quote") or ""
    if "\n" in quote or len(_squash(quote).replace(" ", "")) < MIN_QUOTE_CHARS:
        return None
    wanted = _squash(quote)
    for number, text in index.get(finding.get("file"), []):
        if wanted in text:
            return number
    return None


def verify_findings(findings, index):
    """Keep what the diff proves. Unproven findings keep no text and cannot block.

    The line number is taken from the diff, not the model.
    """
    verified = []
    for finding in findings:
        line = locate(finding, index)
        if line is None:
            verified.append({"severity": "advisory", "class": finding["class"], "file": "", "line": 0, "quote": ""})
        else:
            verified.append({**finding, "line": line})
    return verified


def sanitize(envelope, cli_rc, stripped, schema):
    """Reduce the raw CLI output. Nothing unverified leaves this function."""
    result = {"cli_ok": False, "malformed": False, "verdict": None, "usage": {}, "error_status": None}
    if not isinstance(envelope, dict):
        return result
    status = envelope.get("api_error_status")
    result["error_status"] = status if isinstance(status, int) else None
    usage = envelope.get("usage")
    if isinstance(usage, dict):
        result["usage"] = {k: usage[k] for k in USAGE_KEYS if isinstance(usage.get(k), int)}
    if cli_rc != 0 or envelope.get("is_error") is not False or envelope.get("subtype") != "success":
        return result
    result["cli_ok"] = True
    verdict = envelope.get("structured_output")
    if validate(verdict, schema):
        result["malformed"] = True
        return result
    result["verdict"] = {"reviewed": verdict["reviewed"],
                         "findings": verify_findings(verdict["findings"], diff_index(stripped))}
    return result


def block(tier, reasons, blocking=()):
    return {"outcome": "BLOCK", "tier": tier, "approve": False, "reasons": list(reasons),
            "blocking": list(blocking)}


def owner_approved(reviews, owners, head_sha):
    """True if a code owner's latest review approves this exact commit."""
    wanted = {owner.casefold() for owner in owners or []}
    latest = {}
    for review in reviews or []:
        login = ((review.get("user") or {}).get("login") or "").casefold()
        if login in wanted and review.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            latest[login] = review
    states = list(latest.values())
    if any(r["state"] == "CHANGES_REQUESTED" for r in states):
        return False
    return any(r["state"] == "APPROVED" and r.get("commit_id") == head_sha for r in states)


def human_gate(owner_ok, reasons, outcome="HOLD"):
    """A person decides, and the App never approves. Red until a code owner has."""
    if owner_ok:
        return {"outcome": outcome, "tier": "T2", "approve": False, "blocking": [],
                "reasons": reasons + ["code_owner_approved"]}
    return block("T2", reasons + ["owner_approval_required"])


def app_dismissed(reviews, app_login, head_sha):
    """True if someone dismissed the App's approval of this exact commit.

    An older commit's dismissal is just stale-review dismissal after a push.
    """
    return any((r.get("user") or {}).get("login") == app_login and r.get("state") == "DISMISSED"
               and r.get("commit_id") == head_sha for r in reviews or [])


def review_gap(clean, review_result, schema):
    """Why there is no usable review, or None if there is one."""
    if review_result != "success":
        return "review_did_not_run"
    if not isinstance(clean, dict):
        return "verdict_missing"
    if clean.get("cli_ok") is not True:
        return "review_cli_error"
    if clean.get("malformed") or validate(clean.get("verdict"), schema):
        return "verdict_malformed"
    if clean["verdict"]["reviewed"] is not True:
        return "not_reviewed"
    return None


def decide(tier_doc, clean, review_result, stripped, schema, reviews=None, head_sha=None,
           app_login=None, classify_result="success", data_missing=False):
    """The whole merge decision. Anything short of a proven PASS gets no App approval."""
    if classify_result != "success":
        return block("T2", ["classify_failed"])
    if data_missing:
        return block("T2", ["gate_data_missing"])
    if not isinstance(tier_doc, dict) or not tier_doc.get("classified"):
        return block("T2", ["tier_missing"])
    tier = tier_doc.get("tier")
    if tier not in ("T0", "T1", "T2"):
        return block("T2", ["tier_invalid"])
    if tier_doc.get("draft"):
        return {"outcome": "SKIP", "tier": tier, "approve": False, "reasons": ["draft"], "blocking": []}
    owner_ok = owner_approved(reviews, tier_doc.get("owners"), head_sha)
    # Forks are decided before tier or reasons are read, so the check result cannot
    # tell an outsider whether their text hit the blocklist.
    if not tier_doc.get("same_repo"):
        return human_gate(owner_ok, ["fork_not_auto_reviewed"])
    reasons = sorted({r["code"] for r in tier_doc.get("reasons", [])})
    if tier_doc.get("sticky_block"):
        return block(tier, reasons + ["sticky_block"])

    def approved(level):
        if app_dismissed(reviews, app_login, head_sha):
            return human_gate(owner_ok, reasons + ["app_approval_dismissed"])
        return {"outcome": "PASS", "tier": level, "approve": True, "reasons": reasons, "blocking": []}

    if tier == "T0":
        return approved("T0")
    gap = review_gap(clean, review_result, schema)
    if gap:
        return human_gate(owner_ok, reasons + [gap])
    findings = verify_findings(clean["verdict"]["findings"], diff_index(stripped))
    blocking = sorted({(f["file"], f["line"], f["class"]) for f in findings if f["severity"] == "blocking"})
    if blocking:
        listed = [{"file": path, "line": line, "class": kind} for path, line, kind in blocking]
        return block(tier, reasons + ["blocking_findings"], listed)
    if tier == "T2":
        return human_gate(owner_ok, reasons, "PASS")
    return approved("T1")


def safe_text(text):
    """File paths are attacker-chosen: no markup, no mentions in a public comment."""
    return re.sub(r"[^A-Za-z0-9._/-]", "?", str(text))[:200]


def render_comment(decision, tier_doc):
    """Fixed template. No model prose can reach this: only enums, codes, path:line."""
    tier_doc = tier_doc if isinstance(tier_doc, dict) else {}
    lines = [COMMENT_MARKER, f'**Factory gate: {decision["outcome"]}** (tier {decision["tier"]})']
    if decision["reasons"]:
        lines.append("\nReasons: " + ", ".join(f"`{safe_text(r)}`" for r in decision["reasons"]))
    located = sorted({(r["path"], r.get("line") or 0, r["code"]) for r in tier_doc.get("reasons", []) if r.get("path")})
    if located:
        lines.append("\nPaths:")
        for path, line, code in located[:MAX_LISTED]:
            where = safe_text(path) + (f":{int(line)}" if line else "")
            lines.append(f"- `{where}` ({safe_text(code)})")
    if decision["blocking"]:
        lines.append("\nBlocking findings:")
        for finding in decision["blocking"][:MAX_LISTED]:
            where = f'{safe_text(finding["file"])}:{int(finding["line"])}'
            lines.append(f'- `{where}` ({safe_text(finding["class"])})')
    for reason, note in NOTES.items():
        if reason in decision["reasons"]:
            lines.append(f"\n{note}")
    return "\n".join(lines) + "\n"


def actions(decision, tier_doc):
    outcome, tier = decision["outcome"], decision["tier"]
    same_repo = isinstance(tier_doc, dict) and tier_doc.get("same_repo") is True
    decision["needs_alex"] = outcome in ("BLOCK", "HOLD") or (outcome == "PASS" and tier == "T2")
    # Forks get no comment: a public reason would confirm a blocklisted name.
    decision["post_comment"] = same_repo and outcome != "SKIP" and (outcome != "PASS" or tier != "T0")
    # Only a model's finding is sticky, and only where the App may record it.
    digest = tier_doc.get("diff_hash") if same_repo else None
    if digest and "blocking_findings" in decision["reasons"]:
        decision["sticky_marker"] = sticky_marker(digest)
    return decision


_load_json = _read_json


def _load_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace", newline="") as handle:
            return handle.read()
    except (OSError, TypeError):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--decide", action="store_true")
    parser.add_argument("--envelope")
    parser.add_argument("--cli-rc", type=int, default=1)
    parser.add_argument("--tier")
    parser.add_argument("--verdict")
    parser.add_argument("--review-result", default="")
    parser.add_argument("--reviews")
    parser.add_argument("--head-sha")
    parser.add_argument("--app-login")
    parser.add_argument("--classify-result", default="success")
    parser.add_argument("--gate-data", help="A file classify uploaded. Absent means the artifact expired.")
    parser.add_argument("--diff")
    parser.add_argument("--schema", default=DEFAULT_SCHEMA)
    parser.add_argument("--out", required="--selftest" not in sys.argv)
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    schema = _load_json(args.schema)
    if schema is None:
        print("verdict schema missing", file=sys.stderr)
        return 1
    stripped = _load_text(args.diff)

    if args.sanitize:
        clean = sanitize(_load_json(args.envelope), args.cli_rc, stripped, schema)
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(clean, handle, indent=2)
        print(f'sanitized: cli_ok={clean["cli_ok"]} malformed={clean["malformed"]} '
              f'status={clean["error_status"]} usage={clean["usage"]}')
        return 0

    if not args.decide:
        parser.error("choose --sanitize or --decide")
    tier_doc = _load_json(args.tier)
    try:
        decision = decide(tier_doc, _load_json(args.verdict), args.review_result, stripped, schema,
                          _flatten(_load_json(args.reviews)), args.head_sha, args.app_login,
                          args.classify_result, bool(args.gate_data) and not os.path.exists(args.gate_data))
    except Exception as exc:  # fail closed
        print(f"decide error: {type(exc).__name__}", file=sys.stderr)
        decision = block("T2", ["decide_error"])
    actions(decision, tier_doc)
    decision["comment"] = render_comment(decision, tier_doc)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(decision, handle, indent=2)
    # Outcome only: logs are public, and for a fork it does not vary with the tier.
    print(f'{decision["outcome"]} approve={decision["approve"]}')
    for reason in ("gate_data_missing", "classify_failed"):
        if reason in decision["reasons"]:
            print(f"::error::factory-gate: {NOTES[reason]}")
    return 1 if decision["outcome"] == "BLOCK" else 0


def selftest():
    failed = 0

    def check(name, ok):
        nonlocal failed
        failed += 0 if ok else 1
        print("ok  " if ok else "FAIL", name)

    schema = _load_json(DEFAULT_SCHEMA)
    diff = ("diff --git a/src/app.py b/src/app.py\nindex 1..2 100644\n--- a/src/app.py\n+++ b/src/app.py\n"
            "@@ -10,2 +10,3 @@\n context line stays here\n-    return False\n+    return True  # allow everyone\n+    log(user.email)\n")
    quoted = {"severity": "blocking", "class": "security", "file": "src/app.py", "line": 999,
              "quote": "return True  # allow everyone"}
    envelope = lambda v, **kw: {"is_error": False, "subtype": "success", "structured_output": v,
                                "usage": {"input_tokens": 5, "output_tokens": 2}, **kw}
    tier = lambda t="T1", **kw: {"classified": True, "tier": t, "same_repo": True, "draft": False,
                                 "reasons": [], "owners": ["Owner"], **kw}
    clean = lambda v: sanitize(envelope(v), 0, diff, schema)
    run = lambda t, c, r="success": decide(t, c, r, diff, schema)
    good = {"reviewed": True, "findings": []}

    # the spec's named hostile fixtures
    out = run(tier(), None)
    check("HOSTILE missing verdict blocks", out["outcome"] == "BLOCK" and "verdict_missing" in out["reasons"])
    out = run(tier(), clean({"findings": []}))
    check("HOSTILE verdict without reviewed blocks", out["outcome"] == "BLOCK" and "verdict_malformed" in out["reasons"])
    out = run(tier(), clean({"reviewed": False, "findings": []}))
    check("HOSTILE reviewed:false blocks", out["outcome"] == "BLOCK" and "not_reviewed" in out["reasons"])
    out = run(tier(), clean({"reviewed": "true", "findings": []}))
    check("HOSTILE reviewed as a string blocks", out["outcome"] == "BLOCK")
    unquoted = {**quoted, "quote": "this text is nowhere in the diff"}
    out = run(tier(), clean({"reviewed": True, "findings": [unquoted]}))
    check("HOSTILE unquoted finding demoted to advisory", out["outcome"] == "PASS" and not out["blocking"])
    out = run(tier(), clean({"reviewed": True, "findings": [quoted]}))
    check("quoted blocking finding blocks", out["outcome"] == "BLOCK" and len(out["blocking"]) == 1)
    check("line number comes from the diff, not the model", out["blocking"][0]["line"] == 11)
    check("no model text in the blocking list", set(out["blocking"][0]) == {"file", "line", "class"})

    # quote check edges
    for name, finding in [("too short", {**quoted, "quote": "}"}),
                          ("wrong file", {**quoted, "file": "src/other.py"}),
                          ("multi-line", {**quoted, "quote": "context line\nreturn True"}),
                          ("empty", {**quoted, "quote": ""})]:
        out = run(tier(), clean({"reviewed": True, "findings": [finding]}))
        check(f"quote refused: {name}", out["outcome"] == "PASS" and not out["blocking"])
    spaced = {**quoted, "quote": "   return   True  #  allow   everyone  "}
    check("whitespace differences still match", run(tier(), clean({"reviewed": True, "findings": [spaced]}))["outcome"] == "BLOCK")
    check("removed line can be quoted", run(tier(), clean({"reviewed": True, "findings": [{**quoted, "quote": "return False"}]}))["blocking"][0]["line"] == 11)

    # exfiltration: nothing unverified leaves sanitize
    exfil = {"reviewed": True, "findings": [{**quoted, "quote": "private-account-detail@example.com"}]}
    dumped = json.dumps(sanitize(envelope(exfil), 0, diff, schema))
    check("HOSTILE model text dropped from artifact", "private-account-detail" not in dumped)
    extra = {"reviewed": True, "findings": [], "note": "leak"}
    dumped = json.dumps(sanitize(envelope(extra), 0, diff, schema))
    check("HOSTILE extra field refused and dropped", "leak" not in dumped and '"malformed": true' in dumped)
    dumped = json.dumps(sanitize(envelope(good, result="prose leak"), 0, diff, schema))
    check("HOSTILE envelope prose dropped", "prose leak" not in dumped)
    evil = {**quoted, "file": "`@attacker [x](http://e.vil)`.py"}
    check("HOSTILE file path sanitised for comments", "@" not in safe_text(evil["file"]) and "`" not in safe_text(evil["file"]))

    # fail closed on CLI failure
    for name, env, rc in [("nonzero exit", envelope(good), 1),
                          ("usage limit", {"is_error": True, "subtype": "success", "api_error_status": 429}, 1),
                          ("expired token", {"is_error": True, "subtype": "error_during_execution", "api_error_status": 401}, 1),
                          ("is_error absent", {"subtype": "success", "structured_output": good}, 0),
                          ("not json", None, 0)]:
        out = run(tier(), sanitize(env, rc, diff, schema))
        check(f"HOSTILE CLI failure blocks: {name}", out["outcome"] == "BLOCK" and "review_cli_error" in out["reasons"])
    check("no structured output blocks", run(tier(), sanitize({"is_error": False, "subtype": "success"}, 0, diff, schema))["outcome"] == "BLOCK")
    check("review job failed blocks", run(tier(), clean(good), "failure")["outcome"] == "BLOCK")
    check("review job skipped blocks", run(tier(), None, "skipped")["outcome"] == "BLOCK")
    check("review job cancelled blocks", run(tier(), clean(good), "cancelled")["outcome"] == "BLOCK")
    check("missing tier blocks", run(None, clean(good))["outcome"] == "BLOCK")
    check("unclassified tier doc blocks", run({"tier": "T0", "same_repo": True}, None)["outcome"] == "BLOCK")
    check("unknown tier blocks", run(tier("T9"), clean(good))["outcome"] == "BLOCK")
    tampered = clean({"reviewed": True, "findings": [quoted]})
    tampered["verdict"]["reviewed"] = False
    check("decide re-checks reviewed", run(tier(), tampered)["outcome"] == "BLOCK")

    # outcomes by tier
    out = run(tier("T0"), None, "skipped")
    check("T0 passes and approves with no model", out["outcome"] == "PASS" and out["approve"])
    out = run(tier(), clean(good))
    check("T1 clean review approves", out["outcome"] == "PASS" and out["approve"])
    head = "c" * 40
    approved = [{"user": {"login": "owner"}, "state": "APPROVED", "commit_id": head}]
    unavailable = [("fork", dict(same_repo=False), None, "skipped"),
                   ("too large", {}, None, "skipped"),
                   ("expired token", {}, sanitize({"is_error": True, "subtype": "success", "api_error_status": 401}, 1, diff, schema), "success"),
                   ("reviewed false", {}, clean({"reviewed": False, "findings": []}), "success")]
    for name, extra, verdict, result in unavailable:
        for start in ("T1", "T2"):
            out = decide(tier(start, **extra), verdict, result, diff, schema)
            check(f"REVIEW {name} on {start} stays red with no App approval", out["outcome"] == "BLOCK" and not out["approve"])
            out = decide(tier(start, **extra), verdict, result, diff, schema, approved, head)
            check(f"REVIEW {name} on {start} clears on owner approval, still no App approval",
                  out["outcome"] == "HOLD" and not out["approve"] and out["tier"] == "T2")

    # REVIEW2: these paths exited 0 while owner_backstop assumed CODEOWNERS covered them
    policy = {"tiers": {"t1": ["src/**", "scripts/**"]}}
    for path in ("src/.github/workflows/x.yml", "src/.claude/settings.json", "scripts/.env.local", "src/CLAUDE.MD"):
        fixture = (f"diff --git a/{path} b/{path}\nindex 1111111..2222222 100644\n--- a/{path}\n+++ b/{path}\n"
                   "@@ -1 +1 @@\n-old text\n+new text\n")
        doc = {**classify(fixture, policy, [{"filename": path}], "unused", {"hidden_chars": 0}),
               "classified": True, "same_repo": True, "draft": False, "owners": ["Owner"]}
        out = decide(doc, sanitize(envelope(good), 0, fixture, schema), "success", fixture, schema)
        check(f"REVIEW2 {path} stays red with a clean review", out["outcome"] == "BLOCK" and not out["approve"])
        out = decide(doc, sanitize(envelope(good), 0, fixture, schema), "success", fixture, schema, approved, head)
        check(f"REVIEW2 {path} passes only on owner approval, never by the App", out["outcome"] == "PASS" and not out["approve"])
    check("REVIEW2 owner_backstop is gone", "owner_backstop" not in doc)

    # REVIEW2: a rerun after the artifacts expired
    out = decide(tier(), None, "success", None, schema, data_missing=True)
    check("REVIEW2 expired artifacts block with a clear reason", out["reasons"] == ["gate_data_missing"])
    body = render_comment(actions(out, None), None)
    check("REVIEW2 expiry comment says what to do", "Re-run all jobs or push" in body)
    out = decide(None, None, "skipped", None, schema, classify_result="failure")
    check("failed classify blocks with a clear reason", out["reasons"] == ["classify_failed"])
    check("failed classify beats a green-looking T0", decide(tier("T0"), None, "skipped", diff, schema, classify_result="failure")["outcome"] == "BLOCK")

    # REVIEW2: model BLOCK is sticky, and an owner approval doesn't clear it
    digest = "e" * 64
    done = run(tier(diff_hash=digest), clean({"reviewed": True, "findings": [quoted]}))
    actions(done, tier(diff_hash=digest))
    check("REVIEW2 model block records a marker", done["sticky_marker"] == sticky_marker(digest))
    out = decide(tier(sticky_block=True), None, "skipped", diff, schema, approved, head)
    check("REVIEW2 sticky block holds with no model call", out["outcome"] == "BLOCK" and "sticky_block" in out["reasons"])
    check("REVIEW2 sticky applies on T2 too", decide(tier("T2", sticky_block=True), None, "skipped", diff, schema, approved, head)["outcome"] == "BLOCK")
    gapped = run(tier(diff_hash=digest), None)
    check("a review gap records no marker", "sticky_marker" not in actions(gapped, tier(diff_hash=digest)))
    forked = actions(run(tier(same_repo=False, diff_hash=digest), None), tier(same_repo=False, diff_hash=digest))
    check("forks record no marker", "sticky_marker" not in forked)

    # REVIEW2: dismissal of the App's approval
    gone = [{"user": {"login": "app[bot]"}, "state": "DISMISSED", "commit_id": head}]
    out = decide(tier(), clean(good), "success", diff, schema, gone, head, "app[bot]")
    check("REVIEW2 T1 refuses re-approval after dismissal", out["outcome"] == "BLOCK" and not out["approve"] and "app_approval_dismissed" in out["reasons"])
    out = decide(tier(), clean(good), "success", diff, schema, gone + approved, head, "app[bot]")
    check("a dismissal then an owner approval clears without the App", out["outcome"] == "HOLD" and not out["approve"])
    out = decide(tier(), clean(good), "success", diff, schema, [{**gone[0], "commit_id": "d" * 40}], head, "app[bot]")
    check("stale dismissal of an older commit still re-approves", out["outcome"] == "PASS" and out["approve"])
    out = decide(tier("T0"), None, "skipped", diff, schema, gone, head, "app[bot]")
    check("T0 refuses re-approval after dismissal too", out["outcome"] == "BLOCK" and not out["approve"])

    # content T2 needs an owner, like every other T2
    out = run(tier("T2"), clean(good))
    check("REVIEW content T2 with no owner approval stays red", out["outcome"] == "BLOCK" and "owner_approval_required" in out["reasons"])
    run5 = lambda r, h=head: decide(tier("T2"), clean(good), "success", diff, schema, r, h)
    check("content T2 passes on owner approval", run5(approved)["outcome"] == "PASS" and not run5(approved)["approve"])
    stale = [{**approved[0], "commit_id": "d" * 40}]
    check("REVIEW approval of an older commit does not count", run5(stale)["outcome"] == "BLOCK")
    check("owner login is case-insensitive", owner_approved(approved, ["OWNER"], head))
    check("non-owner approval does not count", run5([{**approved[0], "user": {"login": "someone"}}])["outcome"] == "BLOCK")
    check("later dismissal cancels approval", run5(approved + [{"user": {"login": "owner"}, "state": "DISMISSED"}])["outcome"] == "BLOCK")
    check("changes requested cancels approval", run5(approved + [{"user": {"login": "owner"}, "state": "CHANGES_REQUESTED"}])["outcome"] == "BLOCK")
    check("a comment does not cancel approval", run5(approved + [{"user": {"login": "owner"}, "state": "COMMENTED"}])["outcome"] == "PASS")
    check("no reviews stays red", run5(None)["outcome"] == "BLOCK")

    out = run(tier("T0", same_repo=False), None, "skipped")
    check("fork T0 is not auto-approved", out["outcome"] == "BLOCK" and not out["approve"])
    out = run(tier("T1", draft=True), None, "skipped")
    check("draft skips without approving", out["outcome"] == "SKIP" and not out["approve"])

    # REVIEW: a fork must learn nothing about the blocklist
    hit = [{"code": "content_policy", "path": None, "line": None}]
    clean_doc, hit_doc = tier("T0", same_repo=False), tier("T2", same_repo=False, reasons=hit)
    one, two = run(clean_doc, None, "skipped"), run(hit_doc, None, "skipped")
    check("REVIEW fork outcome identical with and without a blocklist hit", one == two)
    check("REVIEW fork gets no comment", not actions(two, hit_doc)["post_comment"])
    body = render_comment(actions(run(tier("T2", reasons=hit), clean(good)), tier("T2", reasons=hit)), tier("T2", reasons=hit))
    check("REVIEW same-repo comment has no path or line for a hit", "Paths:" not in body and "a.md" not in body)
    check("REVIEW2 public comment uses a generic reason", "blocklist" not in body and "content_policy" in body)

    # REVIEW: verified lines are sorted and deduped
    twice = {"reviewed": True, "findings": [{**quoted, "class": "security"}, {**quoted, "file": "src/app.py", "quote": "return False", "class": "correctness"},
                                            {**quoted, "class": "security"}]}
    out = run(tier(), clean(twice))
    check("REVIEW blocking lines deduped and sorted", [(b["line"], b["class"]) for b in out["blocking"]] == [(11, "correctness"), (11, "security")])

    # comments and follow-up actions
    tier_doc = tier("T1", reasons=[{"code": "x_code", "path": "src/`a`.py", "line": 3}])
    out = actions(run(tier(), clean({"reviewed": True, "findings": [quoted]})), tier())
    body = render_comment(out, tier_doc)
    check("comment leads with the sticky marker", body.split("\n")[0] == COMMENT_MARKER)
    check("comment shows file:line and class only", "`src/app.py:11` (security)" in body and "allow everyone" not in body)
    check("BLOCK flags needs_alex", out["needs_alex"])
    check("T1 PASS does not flag needs_alex", not actions(run(tier(), clean(good)), tier())["needs_alex"])
    check("T0 PASS posts no comment", not actions(run(tier("T0"), None), tier("T0"))["post_comment"])
    check("unknown tier doc posts no comment", not actions(block("T2", ["tier_missing"]), None)["post_comment"])

    # REVIEW: the workflow must not publish derived results or approve a moved head
    gate_path = os.path.join(os.path.dirname(DEFAULT_SCHEMA), "..", ".github", "workflows", "gate.yml")
    gate = _load_text(gate_path) or ""
    artifact = gate[gate.index("name: gate-data"):gate.index("retention-days")]
    check("REVIEW no derived result in a public artifact", "tier.json" not in artifact and "decision" not in artifact)
    check("REVIEW no blocklist outside the decide job", gate.index("FACTORY_NAME_BLOCKLIST:") > gate.index("  decide:"))
    check("REVIEW live head compared before approving", 0 < gate.index('"$live" != "$HEAD_SHA"') < gate.index("event=APPROVE"))
    check("REVIEW comment fetch for the cache is gone from classify", "issues/$PR/comments" not in gate[:gate.index("  decide:")])
    check("REVIEW2 artifacts kept 30 days", gate.count("retention-days: 30") == 2 and "retention-days: 1\n" not in gate)
    caller = _load_text(os.path.join(os.path.dirname(DEFAULT_SCHEMA), "..", "templates", "workflows", "factory-gate.yml")) or ""
    check("REVIEW2 concurrency group includes the head SHA", "pull_request.head.sha }}" in caller.split("concurrency:")[1].split("jobs:")[0])

    # end to end through the CLI: a missing verdict must exit non-zero
    with tempfile.TemporaryDirectory() as tmp:
        paths = {n: os.path.join(tmp, n) for n in ("tier.json", "diff", "decision.json")}
        with open(paths["tier.json"], "w", encoding="utf-8") as handle:
            json.dump(tier(), handle)
        with open(paths["diff"], "w", encoding="utf-8") as handle:
            handle.write(diff)
        sys.argv = ["factory_verdict.py", "--decide", "--tier", paths["tier.json"], "--diff", paths["diff"],
                    "--verdict", os.path.join(tmp, "absent.json"), "--review-result", "success",
                    "--out", paths["decision.json"]]
        check("CLI exits non-zero on BLOCK", main() == 1 and _load_json(paths["decision.json"])["outcome"] == "BLOCK")
        sys.argv = ["factory_verdict.py", "--decide", "--tier", paths["tier.json"], "--diff", paths["diff"],
                    "--verdict", os.path.join(tmp, "absent.json"), "--review-result", "skipped",
                    "--out", paths["decision.json"]]
        with open(paths["tier.json"], "w", encoding="utf-8") as handle:
            json.dump(tier("T2"), handle)
        sys.argv += ["--gate-data", os.path.join(tmp, "absent-strip.json")]
        check("CLI blocks when gate data has expired", main() == 1 and _load_json(paths["decision.json"])["reasons"] == ["gate_data_missing"])

    print(f"factory_verdict selftest: {'FAILED ' + str(failed) if failed else 'passed'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
