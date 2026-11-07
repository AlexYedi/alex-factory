#!/usr/bin/env python3
"""Turn the model's output into a merge decision, deterministically.

Two steps, both fail closed:
  --sanitize (review job) reduces the CLI envelope to schema-checked fields whose
    text is verified against the diff, so no model prose reaches an artifact.
  --decide (decide job) re-verifies that and decides PASS, BLOCK or SKIP.

A PASS needs a positive reviewed:true. Silence is never approval, because an
injected "say nothing" must not read the same as a clean review.
"""
import argparse
import json
import os
import re
import sys
import tempfile

from minischema import validate
from risk_tier import DiffError, parse_diff

MIN_QUOTE_CHARS = 8
USAGE_KEYS = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
DEFAULT_SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "verdict.schema.json")
MAX_LISTED = 20


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


def decide(tier_doc, clean, review_result, stripped, schema):
    """The whole merge decision. Every path that is not a proven PASS is a BLOCK."""
    if not isinstance(tier_doc, dict) or not tier_doc.get("classified"):
        return block("T2", ["tier_missing"])
    tier = tier_doc.get("tier")
    if tier not in ("T0", "T1", "T2"):
        return block("T2", ["tier_invalid"])
    reasons = sorted({r["code"] for r in tier_doc.get("reasons", [])})
    if tier_doc.get("draft"):
        return {"outcome": "SKIP", "tier": tier, "approve": False, "reasons": ["draft"], "blocking": []}
    if not tier_doc.get("same_repo"):
        return block(tier, reasons + ["fork_not_auto_reviewed"])
    # T2 is hard-coded out of approval here, as a backstop to the tier logic.
    passed = {"outcome": "PASS", "tier": tier, "approve": tier in ("T0", "T1"),
              "reasons": reasons, "blocking": []}
    if tier == "T0":
        return passed
    if tier_doc.get("reuse_prior_pass"):
        passed["reasons"] = reasons + ["identical_patch_already_reviewed"]
        return passed
    if review_result != "success":
        return block(tier, reasons + ["review_did_not_run"])
    if not isinstance(clean, dict):
        return block(tier, reasons + ["verdict_missing"])
    if clean.get("cli_ok") is not True:
        return block(tier, reasons + ["review_cli_error"])
    verdict = clean.get("verdict")
    if clean.get("malformed") or validate(verdict, schema):
        return block(tier, reasons + ["verdict_malformed"])
    if verdict["reviewed"] is not True:
        return block(tier, reasons + ["not_reviewed"])
    findings = verify_findings(verdict["findings"], diff_index(stripped))
    blocking = [f for f in findings if f["severity"] == "blocking"]
    if blocking:
        return block(tier, reasons + ["blocking_findings"], blocking)
    return passed


def safe_text(text):
    """File paths are attacker-chosen: no markup, no mentions in a public comment."""
    return re.sub(r"[^A-Za-z0-9._/-]", "?", str(text))[:200]


def render_comment(decision, tier_doc):
    """Fixed template. No model prose can reach this: only enums, codes, path:line."""
    tier_doc = tier_doc if isinstance(tier_doc, dict) else {}
    lines = []
    fingerprint = tier_doc.get("fingerprint")
    if fingerprint and re.fullmatch(r"[0-9a-f]{64}", fingerprint):
        lines.append(f'<!-- factory-gate fingerprint={fingerprint} result={decision["outcome"]} -->')
    else:
        lines.append(f'<!-- factory-gate result={decision["outcome"]} -->')
    lines.append(f'**Factory gate: {decision["outcome"]}** (tier {decision["tier"]})')
    if decision["reasons"]:
        lines.append("\nReasons: " + ", ".join(f"`{safe_text(r)}`" for r in decision["reasons"]))
    located = [r for r in tier_doc.get("reasons", []) if r.get("path")][:MAX_LISTED]
    if located:
        lines.append("\nPaths:")
        for reason in located:
            where = safe_text(reason["path"]) + (f':{int(reason["line"])}' if reason.get("line") else "")
            lines.append(f'- `{where}` ({safe_text(reason["code"])})')
    if decision["blocking"]:
        lines.append("\nBlocking findings:")
        for finding in decision["blocking"][:MAX_LISTED]:
            where = f'{safe_text(finding["file"])}:{int(finding["line"])}'
            lines.append(f'- `{where}` ({safe_text(finding["class"])})')
    if decision["tier"] == "T2" and decision["outcome"] == "PASS":
        lines.append("\nHuman approval required: the App never approves T2.")
    return "\n".join(lines) + "\n"


def actions(decision):
    outcome, tier = decision["outcome"], decision["tier"]
    decision["needs_alex"] = outcome == "BLOCK" or (outcome == "PASS" and tier == "T2")
    decision["post_comment"] = outcome == "BLOCK" or (outcome == "PASS" and tier != "T0")
    return decision


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError, TypeError):
        return None


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
        decision = decide(tier_doc, _load_json(args.verdict), args.review_result, stripped, schema)
    except Exception as exc:  # fail closed
        print(f"decide error: {type(exc).__name__}", file=sys.stderr)
        decision = block("T2", ["decide_error"])
    actions(decision)
    decision["comment"] = render_comment(decision, tier_doc)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(decision, handle, indent=2)
    print(f'{decision["outcome"]} tier={decision["tier"]} approve={decision["approve"]} '
          f'reasons={decision["reasons"]}')
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
                                 "reasons": [], "reuse_prior_pass": False, "fingerprint": "a" * 64, **kw}
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
    out = run(tier("T2"), clean(good))
    check("T2 clean review passes but App never approves", out["outcome"] == "PASS" and not out["approve"])
    out = run(tier("T2", reuse_prior_pass=True), None, "skipped")
    check("T2 reuse never approves", out["outcome"] == "PASS" and not out["approve"])
    out = run(tier(reuse_prior_pass=True), None, "skipped")
    check("identical patch reuses the prior pass", out["outcome"] == "PASS" and out["approve"])
    out = run(tier("T0", same_repo=False), None, "skipped")
    check("fork T0 is not auto-approved", out["outcome"] == "BLOCK" and not out["approve"])
    out = run(tier(same_repo=False, reuse_prior_pass=True), None, "skipped")
    check("fork cannot reuse a prior pass", out["outcome"] == "BLOCK")
    out = run(tier("T1", draft=True), None, "skipped")
    check("draft skips without approving", out["outcome"] == "SKIP" and not out["approve"])

    # comments and follow-up actions
    tier_doc = tier("T1", reasons=[{"code": "x_code", "path": "src/`a`.py", "line": 3}])
    out = actions(run(tier(), clean({"reviewed": True, "findings": [quoted]})))
    body = render_comment(out, tier_doc)
    check("comment has the fingerprint marker", body.split("\n")[0].startswith(f'<!-- factory-gate fingerprint={"a" * 64}'))
    check("comment shows file:line and class only", "`src/app.py:11` (security)" in body and "allow everyone" not in body)
    check("BLOCK flags needs_alex", out["needs_alex"])
    check("T2 PASS flags needs_alex", actions(run(tier("T2"), clean(good)))["needs_alex"])
    check("T1 PASS does not flag needs_alex", not actions(run(tier(), clean(good)))["needs_alex"])
    check("T0 PASS posts no comment", not actions(run(tier("T0"), None))["post_comment"])

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

    print(f"factory_verdict selftest: {'FAILED ' + str(failed) if failed else 'passed'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
