#!/usr/bin/env python3
"""Classify a pull request into a risk tier from its diff, as data.

Runs in factory-gate under pull_request_target. It never checks out or runs PR
code: it reads the diff and file list fetched through the API, and the policy
read from the base SHA. Every doubt resolves upward: unmatched path, parse
failure, missing input and invalid policy all mean T2.
"""
import argparse
import json
import os
import re
import sys
import tempfile
import unicodedata

from minischema import validate

# A policy file can add to these but never remove them: they are the gate's own
# controls, and a bad policy must not be able to downgrade them. These names act
# at any depth, so every entry starts with **/. Matched case-insensitively,
# because macOS and Windows checkouts are case-insensitive.
HARD_T2 = [
    "**/.github/**", "**/CODEOWNERS", "**/CLAUDE.md", "**/AGENTS.md", "**/.claude/hooks/**",
    "**/.claude/settings*.json", "**/.claude/agents/**", "**/.gitignore", "**/.gitleaksignore",
    "**/.gitattributes", "**/.env*", "**/.mcp.json", "**/.husky/**", "**/.githooks/**",
]
TEST_GLOBS = ["tests/**", "**/tests/**", "**/test_*", "**/*_test.*", "**/*.test.*"]
SELFTEST_FLAG = re.compile(r"(?<![\w-])--selftest(?![\w-])")
REGULAR_MODE = "100644"
MODE_REASONS = {"120000": "symlink", "160000": "submodule"}
# A T2 path here means GitHub itself demands a code owner, so the gate need not.
OWNED_PATH_REASONS = ("guarded_path", "unmatched_path")

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
INDEX = re.compile(r"^index [0-9a-f]+\.\.[0-9a-f]+(?: (\d{6}))?$")
C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


class DiffError(ValueError):
    """The diff is not something we can fully account for."""


def glob_re(pattern, flags=0):
    """Translate a path glob: `*` stops at /, `**` crosses it."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(rf"\A{out}\Z", flags)


def matches(path, globs, flags=0):
    return any(glob_re(g, flags).match(path) for g in globs)


# --- diff parsing ------------------------------------------------------------

def _c_unquote(text):
    body, out, i = text[1:-1], bytearray(), 0
    try:
        while i < len(body):
            if body[i] != "\\":
                out += body[i].encode("utf-8")
                i += 1
            elif body[i + 1] in "01234567":
                out.append(int(body[i + 1:i + 4], 8))
                i += 4
            else:
                out.append(C_ESCAPES[body[i + 1]])
                i += 2
    except (IndexError, KeyError, ValueError) as exc:
        raise DiffError(f"bad quoted path: {exc}") from exc
    return out.decode("utf-8", "replace")


def _diff_path(token, prefix):
    """Turn `a/x`, `"a/x"` or /dev/null into a repo path or None."""
    token = token.split("\t")[0]
    if token == "/dev/null":
        return None
    if token.startswith('"'):
        token = _c_unquote(token)
    if not token.startswith(prefix):
        raise DiffError("path without expected prefix")
    return token[len(prefix):]


def _header_paths(rest):
    """Best effort for blocks with no ---/+++ lines (mode-only, binary, empty)."""
    if '"' in rest:
        tokens = re.findall(r'"(?:[^"\\]|\\.)*"|[^\s"]+', rest)
        if len(tokens) == 2:
            return _diff_path(tokens[0], "a/"), _diff_path(tokens[1], "b/")
        return None, None
    size = (len(rest) - 5) // 2
    path = rest[2:2 + size]
    if size > 0 and rest == f"a/{path} b/{path}":
        return path, path
    return None, None


def parse_diff(text):
    """Strict parser for git's diff format.

    Hunks are consumed by their declared line counts, never by prefix-sniffing.
    That is what makes an added line reading `++ b/docs/x`, which appears in the
    diff as `+++ b/docs/x`, stay file content instead of forging a file header.
    Splits on \\n only: str.splitlines also breaks on U+2028 and \\x0b, which
    would let file content fake a line break.
    """
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    changes, i, total = [], 0, len(lines)
    while i < total:
        if not lines[i].startswith("diff --git "):
            raise DiffError(f"expected file header at line {i + 1}")
        old, new = _header_paths(lines[i][len("diff --git "):])
        change = {"old": old, "new": new, "status": "modified", "modes": set(), "binary": False,
                  "lines": []}
        i += 1
        while i < total and not lines[i].startswith(("diff --git ", "@@ ")):
            line = lines[i]
            i += 1
            if line.startswith(("old mode ", "new mode ")):
                change["modes"].add(line.split()[-1])
            elif line.startswith("new file mode "):
                change["status"] = "added"
                change["modes"].add(line.split()[-1])
                change["old"] = None
            elif line.startswith("deleted file mode "):
                change["status"] = "deleted"
                change["modes"].add(line.split()[-1])
                change["new"] = None
            elif line.startswith("index "):
                found = INDEX.match(line)
                if not found:
                    raise DiffError("bad index line")
                if found.group(1):
                    change["modes"].add(found.group(1))
            elif line.startswith(("similarity index ", "dissimilarity index ")):
                pass
            elif line.startswith(("rename from ", "rename to ", "copy from ", "copy to ")):
                kind, side, value = line.split(" ", 2)
                value = _c_unquote(value) if value.startswith('"') else value
                change["old" if side == "from" else "new"] = value
                change["status"] = "renamed" if kind == "rename" else "copied"
            elif line.startswith("--- "):
                change["old"] = _diff_path(line[4:], "a/")
            elif line.startswith("+++ "):
                change["new"] = _diff_path(line[4:], "b/")
            elif line.startswith("Binary files ") or line == "GIT binary patch":
                change["binary"] = True
                while i < total and not lines[i].startswith("diff --git "):
                    i += 1
            else:
                raise DiffError(f"unknown header at line {i}")
        while i < total and lines[i].startswith("@@ "):
            found = HUNK.match(lines[i])
            if not found:
                raise DiffError("bad hunk header")
            old_no, new_no = int(found.group(1)), int(found.group(3))
            old_left = 1 if found.group(2) is None else int(found.group(2))
            new_left = 1 if found.group(4) is None else int(found.group(4))
            i += 1
            while old_left > 0 or new_left > 0:
                if i >= total:
                    raise DiffError("truncated hunk")
                line = lines[i]
                i += 1
                kind = line[:1] or " "
                if kind == "\\":
                    continue
                if kind == "+" and new_left > 0:
                    change["lines"].append(("+", None, new_no, line[1:]))
                    new_no += 1
                    new_left -= 1
                elif kind == "-" and old_left > 0:
                    change["lines"].append(("-", old_no, None, line[1:]))
                    old_no += 1
                    old_left -= 1
                elif kind == " " and old_left > 0 and new_left > 0:
                    change["lines"].append((" ", old_no, new_no, line[1:]))
                    old_no += 1
                    new_no += 1
                    old_left -= 1
                    new_left -= 1
                else:
                    raise DiffError("hunk body does not match its counts")
            if i < total and lines[i].startswith("\\"):
                i += 1
        if change["old"] is None and change["new"] is None:
            raise DiffError("file block with no path")
        changes.append(change)
    return changes


# --- policy ------------------------------------------------------------------

def _refuse_duplicates(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def load_policy(path, schema_path):
    """Return (policy, error). Any failure returns None: everything becomes T2."""
    try:
        with open(path, encoding="utf-8") as handle:
            policy = json.load(handle, object_pairs_hook=_refuse_duplicates)
        with open(schema_path, encoding="utf-8") as handle:
            errors = validate(policy, json.load(handle))
    except (OSError, ValueError, TypeError) as exc:
        return None, type(exc).__name__
    return (None, errors[0]) if errors else (policy, None)


# --- classification ----------------------------------------------------------

def fold(text):
    """Normalise for blocklist matching so look-alikes and hidden chars can't dodge it."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    return text.casefold()


def blocklist_terms(raw):
    terms = [fold(t.strip()) for t in (raw or "").split("\n")]
    return [re.compile(rf"(?<!\w){re.escape(t)}(?!\w)") for t in terms if t]


def code_part(line):
    """The line up to its comment: a marker in a comment proves nothing."""
    quote = None
    for i, char in enumerate(line):
        if quote:
            quote = None if char == quote else quote
        elif char in "\"'":
            quote = char
        elif char == "#" or line.startswith("//", i):
            return line[:i]
    return line


def selftest_hits(line):
    return len(SELFTEST_FLAG.findall(code_part(line)))


def _bad_path(path):
    parts = path.split("/")
    return path.startswith("/") or ".." in parts or any(ord(c) < 32 for c in path)


def path_tier(path, policy):
    """Return (tier, reason). Reason is None for a plain policy match."""
    if _bad_path(path):
        return 2, "unsafe_path"
    if matches(path, HARD_T2, re.IGNORECASE):
        return 2, "guarded_path"
    if policy is None:
        return 2, "policy_invalid"
    tiers = policy["tiers"]
    if matches(path, tiers.get("t2", [])):
        return 2, "guarded_path"
    if matches(path, tiers.get("t1", [])):
        return 1, None
    if matches(path, tiers.get("t0", [])):
        return 0, None
    return 2, "unmatched_path"


def classify(diff_text, policy, api_files=None, blocklist=None, strip_report=None, enforce_blocklist=True):
    """Return the classification document. Tiers only ever move upward."""
    tier, reasons, changes, owner_backstop = 0, [], [], False

    def escalate(code, path=None, line=None):
        nonlocal tier
        tier = 2
        reason = {"code": code, "path": path, "line": line}
        if reason not in reasons:
            reasons.append(reason)

    if diff_text is None:
        escalate("diff_unavailable")
    else:
        try:
            changes = parse_diff(diff_text)
        except DiffError:
            escalate("diff_unparseable")
    if diff_text is not None and not changes and not reasons:
        escalate("empty_diff")

    policy_view = policy or {}
    new_globs = policy_view.get("t2_new_file_globs", [])
    needles = policy_view.get("t2_if_diff_contains", [])
    selftest_globs = policy_view.get("selftest_globs", [])
    terms = blocklist_terms(blocklist)

    for change in changes:
        old, new = change["old"], change["new"]
        for path in dict.fromkeys(p for p in (old, new) if p):
            path_level, reason = path_tier(path, policy)
            tier = max(tier, path_level)
            owner_backstop = owner_backstop or reason in OWNED_PATH_REASONS
            if reason:
                reasons.append({"code": reason, "path": path, "line": None})
            if any(t.search(fold(path)) for t in terms):
                # No path or line: where a term sits is what would confirm it.
                escalate("blocklist_match")
        shown = new or old
        for mode in sorted(change["modes"]):
            if mode != REGULAR_MODE:
                escalate(MODE_REASONS.get(mode, "non_regular_mode"), shown)
        if change["binary"]:
            escalate("binary_file", shown)
        if change["status"] in ("added", "renamed", "copied") and new and matches(new, new_globs):
            escalate("new_content_file", new)
        gone = change["status"] == "deleted" or change["status"] == "renamed"
        if old and gone and matches(old, TEST_GLOBS) and not (new and matches(new, TEST_GLOBS)):
            escalate("deleted_test", old)
        # A pure rename has no hunks to count, so leaving the selftest list is the
        # signal. The gate has no tree, so the list is compared by glob membership.
        if old and gone and matches(old, selftest_globs) and not (new and matches(new, selftest_globs)):
            escalate("selftest_script_left", old)
        lost = gained = 0
        for kind, _, new_no, text in change["lines"]:
            if kind == "+":
                gained += selftest_hits(text)
                if any(t.search(fold(text)) for t in terms):
                    escalate("blocklist_match")
            elif kind == "-":
                lost += selftest_hits(text)
            if kind != " " and any(n in text for n in needles):
                escalate("gate_content", shown, new_no)
        # Per file: a marker moved to another file must not cancel out here.
        if lost > gained:
            escalate("selftest_count_lowered", shown)

    if api_files is None:
        escalate("file_list_unavailable")
    elif changes:
        listed = set()
        for item in api_files:
            listed.update(p for p in (item.get("filename"), item.get("previous_filename")) if p)
        in_diff = {p for c in changes for p in (c["old"], c["new"]) if p}
        if listed != in_diff:
            escalate("file_list_mismatch")

    # An unset secret must not quietly remove the only check on T0's private text.
    if enforce_blocklist and tier == 0 and not terms:
        escalate("blocklist_unconfigured")

    if strip_report is None:
        escalate("strip_report_missing")
    else:
        if strip_report.get("hidden_chars"):
            escalate("hidden_characters")
        if strip_report.get("too_large"):
            escalate("diff_too_large")

    return {"tier": f"T{tier}", "reasons": reasons, "owner_backstop": owner_backstop,
            "paths": sorted({p for c in changes for p in (c["old"], c["new"]) if p})}


def list_selftests(root, policy):
    found = []
    for folder, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv")]
        for name in names:
            full = os.path.join(folder, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if os.path.islink(full) or not matches(rel, policy.get("selftest_globs", [])):
                continue
            with open(full, encoding="utf-8", errors="replace") as handle:
                if any(selftest_hits(line) for line in handle.read().split("\n")):
                    found.append(rel)
    return sorted(found)


def _read(path):
    if not path or not os.path.exists(path):
        return None
    with open(path, encoding="utf-8", errors="replace", newline="") as handle:
        return handle.read()


def _read_json(path):
    text = _read(path)
    try:
        return None if text is None else json.loads(text)
    except ValueError:
        return None


def _flatten(pages):
    """gh api --paginate --slurp returns a list of pages."""
    if pages is None:
        return None
    return [item for page in pages for item in (page if isinstance(page, list) else [page])]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--policy")
    parser.add_argument("--schema", default=os.path.join(os.path.dirname(__file__), "policy-schema.json"))
    parser.add_argument("--print-tests-command", action="store_true")
    parser.add_argument("--list-selftests", metavar="ROOT")
    parser.add_argument("--diff")
    parser.add_argument("--files")
    parser.add_argument("--strip-report")
    parser.add_argument("--same-repo", default="false")
    parser.add_argument("--draft", default="false")
    parser.add_argument("--plan", action="store_true",
                        help="Classify from public data only, to decide whether to run the review.")
    parser.add_argument("--out")
    parser.add_argument("--github-output")
    args = parser.parse_args()
    if args.selftest:
        return selftest()

    policy, policy_error = load_policy(args.policy, args.schema) if args.policy else (None, "no policy")
    if args.print_tests_command or args.list_selftests:
        if policy is None:
            print(f"policy unusable: {policy_error}", file=sys.stderr)
            return 2
        if args.print_tests_command:
            print(policy["tests_command"])
        else:
            print("\n".join(list_selftests(args.list_selftests, policy)))
        return 0

    strip_report = _read_json(args.strip_report)
    blocklist = None if args.plan else os.environ.get("FACTORY_NAME_BLOCKLIST")
    try:
        doc = classify(_read(args.diff), policy, _flatten(_read_json(args.files)), blocklist,
                       strip_report, enforce_blocklist=not args.plan)
    except Exception as exc:  # fail closed: a classifier bug must not read as low risk
        doc = {"tier": "T2", "reasons": [{"code": "classifier_error", "path": None, "line": None}],
               "owner_backstop": False}
        print(f"classifier error: {type(exc).__name__}", file=sys.stderr)
    if policy is None:
        doc["reasons"].append({"code": "policy_invalid", "path": None, "line": None})
        print(f"policy unusable: {policy_error}", file=sys.stderr)
    doc.pop("paths", None)

    same_repo = args.same_repo == "true"
    draft = args.draft == "true"
    if args.plan:
        ready = bool(strip_report) and bool(strip_report.get("prompt"))
        run_review = doc["tier"] != "T0" and same_repo and not draft and ready
        with open(args.github_output, "a", encoding="utf-8") as handle:
            handle.write(f'run_review={"true" if run_review else "false"}\n')
        print(f"run_review={run_review}")
        return 0

    doc.update(same_repo=same_repo, draft=draft, classified=True,
               owners=(policy or {}).get("code_owners", []))
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=2)
    # Workflow logs are public, and a fork could read a tier change as a blocklist hit.
    print("classified")
    return 0


# --- selftest ----------------------------------------------------------------

POLICY = {
    "version": 1, "tests_command": "true", "code_owners": ["owner"], "selftest_globs": ["scripts/*.py"],
    "tiers": {"t0": ["docs/**", "content/**"], "t1": ["scripts/**"],
              "t2": ["scripts/guard_*.py", "migrations/**"]},
    "t2_new_file_globs": ["content/**"], "t2_if_diff_contains": ["GATE_MARKER"],
}
STRIP_OK = {"hidden_chars": 0, "injection_markers": 0, "too_large": False}


def fx_mod(path, added="new text", removed="old text"):
    return (f"diff --git a/{path} b/{path}\nindex 1111111..2222222 100644\n--- a/{path}\n+++ b/{path}\n"
            f"@@ -1 +1 @@\n-{removed}\n+{added}\n")


def fx_rename(old, new):
    return (f"diff --git a/{old} b/{new}\nsimilarity index 100%\nrename from {old}\nrename to {new}\n")


def fx_new(path, mode="100644", body="+hello"):
    return (f"diff --git a/{path} b/{path}\nnew file mode {mode}\nindex 0000000..2222222\n"
            f"--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n{body}\n")


def fx_del(path, body="-gone"):
    return (f"diff --git a/{path} b/{path}\ndeleted file mode 100644\nindex 2222222..0000000\n"
            f"--- a/{path}\n+++ /dev/null\n@@ -1 +0,0 @@\n{body}\n")


def _api(diff):
    try:
        return [{"filename": c["new"] or c["old"], "previous_filename": c["old"] if c["new"] else None}
                for c in parse_diff(diff)]
    except DiffError:
        return []


def _case(name, diff, want, code=None, policy=POLICY, files="auto", block="unused term", strip=STRIP_OK):
    doc = classify(diff, policy, _api(diff or "") if files == "auto" else files, block, strip)
    codes = {r["code"] for r in doc["reasons"]}
    ok = doc["tier"] == want and (code is None or code in codes)
    print(("ok  " if ok else "FAIL"), name, "->", doc["tier"], sorted(codes))
    return 0 if ok else 1


def selftest():
    f = 0
    binary = "diff --git a/docs/a.png b/docs/a.png\nindex 1111111..2222222 100644\nBinary files a/docs/a.png and b/docs/a.png differ\n"
    chmod = "diff --git a/scripts/a.py b/scripts/a.py\nold mode 100644\nnew mode 100755\n"
    exec_mod = fx_mod("scripts/a.py").replace("100644", "100755")
    submodule = "diff --git a/docs/sub b/docs/sub\nnew file mode 160000\nindex 0000000..2222222\n--- /dev/null\n+++ b/docs/sub\n@@ -0,0 +1 @@\n+Subproject commit abc\n"
    forged = (f"diff --git a/docs/a.md b/docs/a.md\nindex 1111111..2222222 100644\n--- a/docs/a.md\n+++ b/docs/a.md\n"
              "@@ -1 +1,3 @@\n-old\n+new\n+++ b/.github/workflows/x.yml\n+diff --git a/x b/x\n")
    spaced = 'diff --git "a/docs/caf\\303\\251 x.md" "b/docs/caf\\303\\251 x.md"\nindex 1111111..2222222 100644\n--- "a/docs/caf\\303\\251 x.md"\n+++ "b/docs/caf\\303\\251 x.md"\n@@ -1 +1 @@\n-a\n+b\n'
    quoted_guard = 'diff --git "a/.github/caf\\303\\251.yml" "b/.github/caf\\303\\251.yml"\nold mode 100644\nnew mode 100644\n'

    # plain tiers
    f += _case("docs edit is T0", fx_mod("docs/a.md"), "T0")
    f += _case("script edit is T1", fx_mod("scripts/a.py"), "T1")
    f += _case("highest tier wins", fx_mod("docs/a.md") + fx_mod("scripts/a.py"), "T1")
    f += _case("policy t2 glob beats t1", fx_mod("scripts/guard_pii.py"), "T2", "guarded_path")
    f += _case("unmatched path defaults to T2", fx_mod("src/app.py"), "T2", "unmatched_path")
    f += _case("hard T2 needs no policy entry", fx_mod("CLAUDE.md"), "T2", "guarded_path")
    f += _case("hard T2 ignores case", fx_mod("claude.md"), "T2", "guarded_path")
    f += _case("nested AGENTS.md", fx_mod("docs/AGENTS.md"), "T2", "guarded_path")
    f += _case("workflow file", fx_mod(".github/workflows/x.yml"), "T2", "guarded_path")
    f += _case("modified content stays T0", fx_mod("content/a.md"), "T0")
    f += _case("new content file is T2", fx_new("content/b.md"), "T2", "new_content_file")
    # hostile: renames
    f += _case("HOSTILE rename into guarded path", fx_rename("docs/a.md", ".github/workflows/x.yml"), "T2", "guarded_path")
    f += _case("HOSTILE rename out of guarded path", fx_rename("scripts/guard_pii.py", "docs/a.py"), "T2", "guarded_path")
    f += _case("HOSTILE rename into new content", fx_rename("docs/a.md", "content/b.md"), "T2", "new_content_file")
    f += _case("rename within T0 stays T0", fx_rename("docs/a.md", "docs/b.md"), "T0")
    # hostile: modes
    f += _case("HOSTILE symlink", fx_new("docs/link", "120000", "+../.env"), "T2", "symlink")
    f += _case("HOSTILE submodule", submodule, "T2", "submodule")
    f += _case("HOSTILE exec bit added", chmod, "T2", "non_regular_mode")
    f += _case("HOSTILE existing exec file", exec_mod, "T2", "non_regular_mode")
    f += _case("HOSTILE binary in T0 path", binary, "T2", "binary_file")
    # hostile: forged headers
    f += _case("HOSTILE added line forging headers", forged, "T0")
    doc = classify(forged, POLICY, _api(forged), "unused term", STRIP_OK)
    ok = doc["paths"] == ["docs/a.md"]
    f += 0 if ok else 1
    print("ok  " if ok else "FAIL", "forged lines are not files", doc["paths"])
    f += _case("quoted unicode path parses", spaced, "T0")
    f += _case("quoted guarded path", quoted_guard, "T2", "guarded_path")
    # hostile: test ratchet
    f += _case("HOSTILE deleted test file", fx_del("scripts/test_a.py"), "T2", "deleted_test")
    f += _case("HOSTILE test renamed out of test glob", fx_rename("scripts/test_a.py", "scripts/a_helper.py"), "T2", "deleted_test")
    f += _case("HOSTILE selftest removed", fx_mod("scripts/a.py", "pass", "if '--selftest' in sys.argv:"), "T2", "selftest_count_lowered")
    f += _case("selftest kept is fine", fx_mod("scripts/a.py", "x --selftest", "y --selftest"), "T1")
    f += _case("gate content marker", fx_mod("scripts/a.py", "GATE_MARKER = 1"), "T2", "gate_content")
    # hostile: blocklist
    f += _case("blocklist in added line", fx_mod("docs/a.md", "met Jane Example today"), "T2", "blocklist_match", block="jane example")
    f += _case("HOSTILE blocklist split by zero-width", fx_mod("docs/a.md", "met Ja​ne Example"), "T2", "blocklist_match", block="jane example")
    f += _case("HOSTILE blocklist fullwidth", fx_mod("docs/a.md", "Ｊａne Example"), "T2", "blocklist_match", block="jane example")
    f += _case("blocklist in path", fx_mod("docs/jane-example/a.md"), "T2", "blocklist_match", block="jane-example")
    doc = classify(fx_mod("docs/a.md", "met Jane Example"), POLICY, _api(fx_mod("docs/a.md")), "jane example", STRIP_OK)
    hits = [r for r in doc["reasons"] if r["code"] == "blocklist_match"]
    ok = len(hits) == 1 and hits[0]["path"] is None and hits[0]["line"] is None
    f += 0 if ok else 1
    print("ok  " if ok else "FAIL", "HOSTILE blocklist reason carries no path or line")
    f += _case("blocklist only on whole words", fx_mod("docs/a.md", "planet"), "T0", block="plane")
    # fail closed
    f += _case("HOSTILE unset blocklist removes T0", fx_mod("docs/a.md"), "T2", "blocklist_unconfigured", block=None)
    f += _case("blank blocklist removes T0", fx_mod("docs/a.md"), "T2", "blocklist_unconfigured", block=" \n")
    f += _case("unset blocklist leaves T1 alone", fx_mod("scripts/a.py"), "T1", block=None)
    f += _case("unparseable diff", "garbage\n", "T2", "diff_unparseable")
    f += _case("truncated hunk", "diff --git a/docs/a b/docs/a\n--- a/docs/a\n+++ b/docs/a\n@@ -1,5 +1,5 @@\n-x\n", "T2", "diff_unparseable")
    f += _case("missing diff", None, "T2", "diff_unavailable")
    f += _case("empty diff", "", "T2", "empty_diff")
    f += _case("no policy", fx_mod("docs/a.md"), "T2", "policy_invalid", policy=None)
    f += _case("missing file list", fx_mod("docs/a.md"), "T2", "file_list_unavailable", files=None)
    f += _case("file list mismatch", fx_mod("docs/a.md"), "T2", "file_list_mismatch", files=[{"filename": "docs/z.md"}])
    f += _case("missing strip report", fx_mod("docs/a.md"), "T2", "strip_report_missing", strip=None)
    f += _case("hidden characters", fx_mod("docs/a.md"), "T2", "hidden_characters", strip={"hidden_chars": 2})
    f += _case("agent repo text is no longer a false T2", fx_mod("scripts/a.py", "system prompt builder"), "T1")
    f += _case("too large", fx_mod("docs/a.md"), "T2", "diff_too_large", strip={"too_large": True})

    # globs
    glob_cases = [("docs/**", "docs/a/b.md", True), ("**/x.md", "x.md", True), ("**/x.md", "a/b/x.md", True),
                  ("scripts/*.py", "scripts/a.py", True), ("scripts/*.py", "scripts/a/b.py", False),
                  ("docs/**", "docsish/a", False), ("a.md", "b/a.md", False)]
    for pattern, path, want in glob_cases:
        ok = bool(glob_re(pattern).match(path)) == want
        f += 0 if ok else 1
        print("ok  " if ok else "FAIL", "glob", pattern, path)

    # reviewer inputs: guarded names at any depth, any case
    f += _case("REVIEW nested claude settings", fx_mod("docs/reference/.claude/settings.json"), "T2", "guarded_path")
    f += _case("REVIEW nested gitattributes", fx_mod("docs/.gitattributes"), "T2", "guarded_path")
    f += _case("REVIEW nested gitattributes, other case", fx_mod("docs/.GITATTRIBUTES"), "T2", "guarded_path")
    f += _case("nested github dir", fx_mod("docs/.github/x.yml"), "T2", "guarded_path")
    f += _case("nested gitignore", fx_mod("scripts/.gitignore"), "T2", "guarded_path")

    # reviewer inputs: ratchet evasions
    f += _case("REVIEW marker moved to a comment", fx_mod("scripts/a.py", "# --selftest", "if '--selftest' in sys.argv:"), "T2", "selftest_count_lowered")
    f += _case("REVIEW marker moved to a // comment", fx_mod("scripts/a.js", "// --selftest", "if (argv.has('--selftest')) {"), "T2", "selftest_count_lowered")
    f += _case("REVIEW marker moved to another file",
               fx_mod("scripts/a.py", "pass", "if '--selftest' in sys.argv:") + fx_mod("scripts/b.py", "if '--selftest' in sys.argv:", "pass"),
               "T2", "selftest_count_lowered")
    f += _case("REVIEW pure rename out of the selftest list", fx_rename("scripts/a.py", "src_helpers/a.py"), "T2", "selftest_script_left")
    f += _case("REVIEW pure rename deeper, out of the glob", fx_rename("scripts/a.py", "scripts/sub/a.py"), "T2", "selftest_script_left")
    f += _case("rename inside the selftest list is fine", fx_rename("scripts/a.py", "scripts/b.py"), "T1")
    f += _case("deleted selftest script", fx_del("scripts/a.py"), "T2", "selftest_script_left")
    ok = code_part("x = '# not a comment'  # real") == "x = '# not a comment'  "
    f += 0 if ok else 1
    print("ok  " if ok else "FAIL", "comment finder respects quotes")

    # reviewer input: the patch-id cache is gone, so a moved hunk gets a fresh review
    ok = "patch_id" not in globals() and "prior_pass" not in globals()
    f += 0 if ok else 1
    print("ok  " if ok else "FAIL", "REVIEW no patch-id cache to reuse a PASS")

    # who backs a T2 decision: GitHub (owned path) or the gate (content-based)
    owned = classify(fx_mod("migrations/1.sql"), POLICY, _api(fx_mod("migrations/1.sql")), "t", STRIP_OK)
    unlisted = classify(fx_mod("src/a.py"), POLICY, _api(fx_mod("src/a.py")), "t", STRIP_OK)
    ratchet = classify(fx_del("scripts/test_a.py"), POLICY, _api(fx_del("scripts/test_a.py")), "t", STRIP_OK)
    new_file = classify(fx_new("content/b.md"), POLICY, _api(fx_new("content/b.md")), "t", STRIP_OK)
    mixed_diff = fx_del("scripts/test_a.py") + fx_mod("migrations/1.sql")
    mixed = classify(mixed_diff, POLICY, _api(mixed_diff), "t", STRIP_OK)
    ok = owned["owner_backstop"] and unlisted["owner_backstop"] and mixed["owner_backstop"]
    ok = ok and not ratchet["owner_backstop"] and not new_file["owner_backstop"]
    f += 0 if ok else 1
    print("ok  " if ok else "FAIL", "owner backstop only where a path forces a code owner")

    # policy parsing, including the shipped template
    here = os.path.dirname(os.path.abspath(__file__))
    with tempfile.TemporaryDirectory() as tmp:
        bad = os.path.join(tmp, "bad.json")
        for text, name in [('{"version": 1, "version": 2}', "duplicate key"), ("version: 1\n", "not JSON"),
                           ('{"version": 1}', "schema: missing keys")]:
            with open(bad, "w", encoding="utf-8") as handle:
                handle.write(text)
            got = load_policy(bad, os.path.join(here, "policy-schema.json"))[0]
            f += 0 if got is None else 1
            print("ok  " if got is None else "FAIL", "policy refused:", name)
        for name, text in [("a.py", "x = '--selftest'\n"), ("b.py", "nothing\n")]:
            os.makedirs(os.path.join(tmp, "scripts"), exist_ok=True)
            with open(os.path.join(tmp, "scripts", name), "w", encoding="utf-8") as handle:
                handle.write(text)
        ok = list_selftests(tmp, POLICY) == ["scripts/a.py"]
        f += 0 if ok else 1
        print("ok  " if ok else "FAIL", "list_selftests finds markers only")
    template = os.path.join(here, "..", "templates", "factory-tiers.json")
    policy, error = load_policy(template, os.path.join(here, "policy-schema.json"))
    f += 0 if policy else 1
    print("ok  " if policy else "FAIL", "shipped template policy loads", error or "")

    print(f"risk_tier selftest: {'FAILED ' + str(f) if f else 'passed'}")
    return 1 if f else 0


if __name__ == "__main__":
    sys.exit(main())
