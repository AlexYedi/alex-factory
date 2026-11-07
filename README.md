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

`factory-gate` has three jobs, each in its own environment:

1. **classify** fetches the diff and file list through the API as data, reads policy from
   the base SHA, and assigns a tier.
2. **review** (T1 and T2, same-repo, not draft) runs `claude -p` in an empty directory with
   no tools, no settings and no MCP. Its input is the contract, the overlay and a stripped
   diff. It never sees a PR title, body, comment or commit message.
3. **decide** validates the verdict, then acts as the App. It is the only job that writes.

The model's only output is JSON with no free-text field, and every quote must exist in the
diff. So an injected "approve this" can at worst produce a verdict, which a stdlib step then
checks. A PASS needs a positive `reviewed: true`; a missing verdict, CLI error, usage limit
or expired token is a BLOCK.

### Tiers

| Tier | What | Review | Merge |
|---|---|---|---|
| T0 | Listed reference and evidence paths, text only, blocklist clean | none | App approves |
| T1 | Listed code paths | model | App approves on PASS |
| T2 | Everything else | model | a human approves; the App never does |

Doubt always resolves to T2: unmatched path, unparseable diff, missing input, invalid policy,
symlink, submodule, non-100644 mode, binary, a deleted test, a lower selftest count, hidden
Unicode, injection phrasing, or an unset blocklist.

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

### 2. Create three environments

The secrets must be **environment** secrets. A same-repo PR can add a workflow that reads any
repository-level secret; a branch restriction on the environment is what stops that.

```bash
R=OWNER/REPO
for e in factory-classify factory-review factory-decide; do
  gh api -X PUT "repos/$R/environments/$e" --input - <<'JSON'
{"deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
JSON
  gh api -X POST "repos/$R/environments/$e/deployment-branch-policies" -f name=main -f type=branch
done

# List the terms that must never auto-merge, one per line. If you have none,
# set any placeholder line: an unset blocklist makes T0 unreachable by design.
gh secret set FACTORY_NAME_BLOCKLIST --env factory-classify -R "$R" < blocklist.txt
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
| `workflows/scan.yml` (if no check named `scan` exists) | `.github/workflows/scan.yml` |
| `factory-tiers.yml` | `.github/factory-tiers.yml` |
| `factory-overlay.md` | `.github/factory-overlay.md` |
| `CODEOWNERS` | `.github/CODEOWNERS` |

Then:

1. Replace `CORE_SHA` in both caller workflows (it appears twice in each) and `YOUR_APP_SLUG`.
2. Edit the tiers for your paths. Set `tests_command`.
3. Keep `CODEOWNERS` in step with the tiers. It can't express "new file", which is why the App
   withholding approval, not CODEOWNERS, is what enforces that T2 rule.
4. Merge this PR yourself. `pull_request_target` only runs once the caller is on the base branch.

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
# Optional private terms, one per line. Inside .git, so it can't be committed.
$EDITOR .git/info/factory-private-names
```

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
- **Rebasing onto a changed base reuses a prior pass** when the patch is identical.
- **Token expiry has no alert yet.** An expired token fails closed, so T1 PRs block.
