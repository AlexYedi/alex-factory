# alex-factory

A portable, risk-tiered review and merge gate for repositories where AI agents write
most of the code. Low-risk changes merge on deterministic checks and an independent
model review. High-risk paths always wait for a human.

Status: core v0. Not yet proven on a live repository; see [What is not verified](#what-is-not-verified).

## How it works

Two workflows, split by trust.

| | `factory-tests` | `factory-gate` |
|---|---|---|
| Trigger | `pull_request` | `pull_request_target` |
| Definition comes from | PR head | base branch, so a PR can't edit its own gate |
| Runs PR code | yes, and assumed hostile | never |
| Secrets | none | one credential per job |

`factory-gate` has three jobs:

1. **classify** holds no secrets. It fetches the diff and file list through the API as data,
   reads policy from the base SHA, and works out whether a review is needed. It hands on only
   data that is already public.
2. **review** (T1 and T2, same-repo, not draft) runs `claude -p` in an empty directory with
   no tools, no settings and no MCP. Its input is the contract, the overlay and a stripped
   diff. It never sees a PR title, body, comment or commit message.
3. **decide** works out the tier with the blocklist, validates the verdict, reads reviews
   live, and acts as the App. It is the only job that writes.

The model's only output is JSON with no free-text field, and every quote must exist in the
diff. So an injected "approve this" can at worst produce a verdict, which a stdlib step then
checks. A PASS needs a positive `reviewed: true`.

If the review can't speak (fork, too large, expired token, usage limit, missing verdict), a
person decides and the App never approves. The check exits 0 where a changed path is owned in
CODEOWNERS, because GitHub then demands that person. Otherwise it stays red until a code owner
has approved this exact commit.

Logs and artifacts are public, so tier and reasons never reach either. A fork gets no comment,
and its check result doesn't vary with the blocklist.

### Tiers

| Tier | What | Review | Merge |
|---|---|---|---|
| T0 | Listed reference and evidence paths, text only, blocklist clean | none | App approves |
| T1 | Listed code paths | model | App approves on PASS |
| T2 | Everything else | model | a human approves; the App never does |

Doubt always resolves to T2: unmatched path, unparseable diff, missing input, invalid policy,
symlink, submodule, non-100644 mode, binary, a deleted test, a script leaving the selftest
list, a file losing a `--selftest` flag, hidden Unicode, or an unset blocklist.

## Adopting it in a repository

Throughout, `OWNER/REPO` is your repository and `CORE_SHA` is the full commit SHA of this
repository that you are adopting.

### 1. Create the GitHub App (once per account)

1. Settings, Developer settings, GitHub Apps, New GitHub App.
2. Repository permissions: **Pull requests: Read and write**, **Contents: Read-only**.
3. Webhook: **Active off**. Install on: **Only on this account**.
4. Generate a private key and note the App ID and slug.
5. Install the App on `OWNER/REPO`.

The App can approve and comment. It cannot push, and it can never satisfy CODEOWNERS.

### 2. Create two environments

The secrets must be **environment** secrets. A same-repo PR can add a workflow that reads any
repository-level secret; a branch restriction on the environment is what stops that.

```bash
R=OWNER/REPO
for e in factory-review factory-decide; do
  gh api -X PUT "repos/$R/environments/$e" --input - <<'JSON'
{"deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
JSON
  gh api -X POST "repos/$R/environments/$e/deployment-branch-policies" -f name=main -f type=branch
done

# List the terms that must never auto-merge, one per line. If you have none,
# set any placeholder line: an unset blocklist makes T0 unreachable by design.
gh secret set FACTORY_NAME_BLOCKLIST --env factory-decide -R "$R" < blocklist.txt
claude setup-token   # then paste the token below
gh secret set CLAUDE_CODE_OAUTH_TOKEN --env factory-review -R "$R"
gh secret set FACTORY_APP_ID --env factory-decide -R "$R" --body "APP_ID"
gh secret set FACTORY_APP_PRIVATE_KEY --env factory-decide -R "$R" < app-private-key.pem
```

### 3. Add the repository files

| From `templates/` | To |
|---|---|
| `workflows/factory-gate.yml` | `.github/workflows/factory-gate.yml` |
| `workflows/factory-tests.yml` | `.github/workflows/factory-tests.yml` |
| `workflows/factory-review-relay.yml` | `.github/workflows/factory-review-relay.yml` |
| `workflows/factory-gate-rerun.yml` | `.github/workflows/factory-gate-rerun.yml` |
| `workflows/scan.yml` (if no check named `scan` exists) | `.github/workflows/scan.yml` |
| `factory-tiers.json` | `.github/factory-tiers.json` |
| `factory-overlay.md` | `.github/factory-overlay.md` |
| `CODEOWNERS` | `.github/CODEOWNERS` |

Then:

1. Replace `CORE_SHA` in both caller workflows (it appears twice in each) and `YOUR_APP_SLUG`.
2. Edit the tiers for your paths, using the policy reference below. Set `tests_command` and
   `code_owners`.
3. Keep `CODEOWNERS` in step with the tiers. Every path you list under `t2`, and the default,
   must be owned there: the gate exits 0 on those paths and trusts GitHub to demand the owner.
4. Merge this PR yourself. `pull_request_target` only runs once the caller is on the base branch.

Policy reference. Paths use `*` (within a folder) and `**` (across folders); anything not
listed is T2. `.github/**`, `CODEOWNERS`, `CLAUDE.md`, `AGENTS.md`, hooks, settings and agent
definitions are T2 at any depth, whatever the policy says.

| Key | Meaning |
|---|---|
| `tests_command` | Shell command `factory-tests` runs on the PR head. Use `"true"` for none. |
| `code_owners` | Logins whose approval clears T2 that CODEOWNERS can't enforce. No teams. |
| `selftest_globs` | Files run with `--selftest` if they contain it outside a comment. |
| `tiers.t0` | Auto-merge with no model review: text-only reference and evidence paths. |
| `tiers.t1` | Model review, then App approval. |
| `tiers.t2` | A human approves. Wins over `t1` and `t0`. |
| `t2_new_file_globs` | Editable at a lower tier, but a brand-new file here is T2. |
| `t2_if_diff_contains` | Literal strings that make a change T2, e.g. skills touching a gate. |

### 4. Set the ruleset on `main`

| Setting | Value |
|---|---|
| Required checks | `scan`, `factory-tests / factory-tests`, `factory-gate / factory-gate` |
| Check source for each | GitHub Actions (`integration_id: 15368`) |
| Require branches up to date | on |
| Required approving reviews | 1 |
| Dismiss stale approvals | on |
| Require review from code owners | on |
| Allowed merge methods | squash |

Repository settings: allow auto-merge on. "Allow GitHub Actions to create and approve pull
requests" stays **off**: approval comes from the App, never from `GITHUB_TOKEN`.

Reusable workflows report as `<caller job> / <called job>`, which is why two required
names are doubled. Confirm the exact strings on your first PR before saving the ruleset.

### 5. Install the local hook

Push is the publish point on a public repository, so the check that matters most runs first.

```bash
cp templates/pre-push .git/hooks/pre-push && chmod +x .git/hooks/pre-push
# Private terms, one per line. Inside .git, so it can't be committed.
$EDITOR .git/info/factory-private-names
```

The hook warns if that list is empty. It blocks binary files, which it can't scan; after
checking one yourself, push with `FACTORY_ALLOW_BINARY=1 git push`.

### 6. Prove it on trial PRs

Work through [What is not verified](#what-is-not-verified) before enabling auto-merge. Use one
T0 change, one T1 change, one T2 change and one PR that adds a workflow reading each secret.

## Development

Stdlib Python only. Every script has a selftest, including hostile fixtures.

```bash
for s in factory/minischema.py factory/risk_tier.py factory/strip_untrusted.py \
         factory/factory_verdict.py templates/pre-push; do
  python3 "$s" --selftest
done
```

## What is not verified

Everything below needs a live GitHub repository. None of it has been exercised yet.

- `workflow_call` under `pull_request_target`: that the definition really comes from the base
  branch, and that `github.event.pull_request` reaches the called workflow.
- Environment secrets inside a reusable workflow with `secrets: inherit`.
- The relay and rerun chain: `workflow_run.head_sha` matching the PR head, finding the check
  by name, and re-running a single job keeping the original event and artifacts. If it fails,
  the check stays red and a manual re-run of the job has the same effect.
- Environment branch policies refusing a PR run, and a PR targeting a non-main base.
- A GitHub App approval counting toward the required review count.
- Exact required-check context names, and `integration_id` pinning for reusable workflows.
- `actions/checkout` of this public repository under `permissions: {}`.
- The compare API returning a diff for a fork's head SHA. A failure resolves to T2.
- `claude -p` with `CLAUDE_CODE_OAUTH_TOKEN`, on a Linux runner, under `env -i`.

## Known limits

- **A required check name can be forged.** A PR adding a workflow with the same job name can
  report that check from GitHub Actions too, and pinning `integration_id` doesn't prevent
  this. The control that holds is the review requirement: such a PR touches `.github/**`, is
  T2, and only a human can approve it.
- **Model review is a filter, not a proof.** Stripping and phrase matching are one layer. An
  injection the model obeys can still suppress a finding on a T1 change.
- **The CLI is pinned by version, not by integrity hash.** A lockfile would close that.
- **A decoy can satisfy the selftest ratchet.** Moving `--selftest` into a comment escalates,
  but moving it into an unused string does not.
- **Selftest lists are compared by glob, not by content.** The gate has no tree, so any rename
  or delete leaving `selftest_globs` escalates, even for a file with no selftest.
- **Owner approval is only as strong as the owner's token.** An agent session holding that
  login can approve on its behalf. Run sessions under a separate identity.
- **A model BLOCK on T2 can't be cleared by approval.** Fix the code or use admin bypass.
- **Token expiry has no alert yet.** An expired token fails closed, so T1 PRs wait for a person.
