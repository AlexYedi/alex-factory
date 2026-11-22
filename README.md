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
person decides and the App never approves. All T2 stays red until a code owner has approved
this exact commit: `code_owners` in the policy, read live from the PR's reviews.

A model BLOCK, on T1 or T2, is sticky for that diff. An empty commit or a rebase can't re-roll
it and no model call is spent; only changing the code gets a new review.

Logs and artifacts are public, so tier and reasons never reach either. A fork gets no comment,
and its check result doesn't vary with the blocklist.

### Tiers

| Tier | What | Review | Merge |
|---|---|---|---|
| T0 | Listed reference and evidence paths, text only, blocklist clean | none | App approves |
| T1 | Listed code paths | model | App approves on PASS |
| T2 | Everything else | model | a code owner approves; the App never does |

Doubt always resolves to T2: unmatched path, unparseable diff, missing input, invalid policy,
symlink, submodule, non-100644 mode, binary, a deleted test, a script leaving the selftest
list, a file losing a `--selftest` flag, hidden Unicode, or an unset blocklist.

## Adopting it in a repository

Throughout, `OWNER/REPO` is your repository and `CORE_SHA` is the full commit SHA of this
repository that you are adopting.

### 1. Create the GitHub App (once per account)

1. Settings, Developer settings, GitHub Apps, New GitHub App.
2. Repository permissions: **Pull requests: Read and write**, **Checks: Read and write**,
   **Contents: Read-only**.
3. Webhook: **Active off**. Install on: **Only on this account**.
4. Generate a private key and note the App ID and slug.
5. Install the App on `OWNER/REPO`. Use one App per gated repository (see Known limits).
6. When you change a permission later, accept it on the installation too (Settings,
   Applications, the App, Review request). Until then the token can't be minted and every PR
   goes red with no comment.

The App can approve, comment and post the `factory-verdict` check. It cannot push. Its approval
doesn't count toward GitHub's required reviews (it isn't a collaborator), so the ruleset relies
on `factory-verdict` instead.

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
gh variable set FACTORY_APP_CLIENT_ID --env factory-decide -R "$R" --body "CLIENT_ID"   # Iv..., App settings > General
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

1. Replace `CORE_SHA` in both caller workflows (it appears twice in each), `YOUR_APP_SLUG`, and
   every `YOUR_LOGIN` in `CODEOWNERS` and `factory-tiers.json`. Until you do, `factory-gate` fails
   with an error naming what's left.
2. Edit the tiers for your paths, using the policy reference below. Set `tests_command` and
   `code_owners`.
3. Keep `CODEOWNERS` in step with the tiers, so GitHub asks the right person. The gate doesn't
   rely on it: it enforces T2 itself.
4. Merge this PR yourself. `pull_request_target` only runs once the caller is on the base branch.

Policy reference. Paths use `*` (within a folder) and `**` (across folders); anything not
listed is T2. `.github/**`, `CODEOWNERS`, `CLAUDE.md`, `AGENTS.md`, hooks, settings and agent
definitions are T2 at any depth, whatever the policy says.

| Key | Meaning |
|---|---|
| `tests_command` | Shell command `factory-tests` runs on the PR head. Use `"true"` for none. |
| `code_owners` | Logins whose approval clears T2. No teams. |
| `selftest_globs` | Files run with `--selftest` if they contain it outside a comment. |
| `tiers.t0` | Auto-merge with no model review: text-only reference and evidence paths. |
| `tiers.t1` | Model review, then App approval. |
| `tiers.t2` | A human approves. Wins over `t1` and `t0`. |
| `t2_new_file_globs` | Editable at a lower tier, but a brand-new file here is T2. |
| `t2_if_diff_contains` | Literal strings that make a change T2, e.g. skills touching a gate. |

### 4. Set the ruleset on `main`

| Setting | Value |
|---|---|
| Required checks | `scan`, `factory-tests / factory-tests`, `factory-gate / factory-gate`, `factory-verdict` |
| Check source | GitHub Actions (`integration_id: 15368`) for the first three; your App (`integration_id` = App ID) for `factory-verdict` |
| Require branches up to date | on |
| Required approving reviews | 0 |
| Dismiss stale approvals | on |
| Require review from code owners | on (GitHub stops enforcing it at 0 approvals; T2 is enforced by the gate) |
| Allowed merge methods | squash |

Why 0 approvals and an App check. GitHub doesn't count the App's approval, so with 1 required
every PR would need a person, including T0 and T1. At 0, GitHub enforces no review at all, so
the gate's verdict has to be unforgeable. A GitHub Actions check isn't: a PR can add a workflow
whose job has the same name and passes. `factory-verdict` can only be posted with the App key,
which only a run from `main` can reach. It is the check that matters; the others stay required
so a red job is visible on the PR.

Order matters. Lowering approvals before `factory-verdict` is required leaves `main` guarded only
by checks a PR can fake.

1. Merge the core version that posts `factory-verdict`, with approvals still at 1.
2. Open any PR and confirm `factory-verdict` appears, from the App.
3. Add `factory-verdict` (App source) to the required checks.
4. Only then set required approvals to 0.

The gate is the only veto at 0 approvals: a code owner's latest "Request changes" blocks every
tier until that owner approves.

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

Work through [What is not verified](#what-is-not-verified) before enabling auto-merge. Every T2
merge depends on the relay and rerun chain, or on someone re-running the job by hand. Use one
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
- ~~A GitHub App approval counting toward the required review count.~~ It doesn't, which is why
  `factory-verdict` exists.
- Exact required-check context names, and `integration_id` pinning for reusable workflows.
- `actions/checkout` of this public repository under `permissions: {}`.
- The compare API returning a diff for a fork's head SHA. A failure resolves to T2.
- `claude -p` with `CLAUDE_CODE_OAUTH_TOKEN`, on a Linux runner, under `env -i`.
- Which of several `factory-verdict` runs on one commit GitHub counts (assumed the latest).
- That code-owner review is unenforced at 0 approvals in every case. If GitHub still enforces it,
  unowned T0 and T1 paths are unaffected, but owned paths would also need an owner review.

## Known limits

- **GitHub Actions check names can be forged.** A PR adding a workflow with the same job name
  can report `scan`, `factory-tests` or `factory-gate` too, and pinning `integration_id` doesn't
  prevent it. The control that holds is `factory-verdict`, which only the App key can post.
- **Re-checking after a review relies on PR-controlled workflows.** A dismissal or changes-request
  only takes effect when decide re-runs, through the relay (which runs from the PR head) and the
  rerun job (which finds the job by name). A PR that breaks either touches `.github/**`, so it is
  T2 and needed an owner's approval; the gap is an owner retracting after approving. Re-run the
  job by hand, or push, after retracting.
- **The App key is the trust root for every repo it is installed on.** Any repo holding the key
  can mint a token for another installed repo and post `factory-verdict` there. Use one App per
  gated repo, or install it only where the key sits under the same main-only environment.
- **A stale success can outlive a failed re-run on the same commit.** If a re-run can't open its
  check, `factory-gate` goes red but the earlier `factory-verdict` success stays. Keep
  `factory-gate / factory-gate` required as that backstop.
- **Model review is a filter, not a proof.** Stripping and phrase matching are one layer. An
  injection the model obeys can still suppress a finding on a T1 change.
- **The CLI is pinned by integrity hash.** The review job runs `npm ci` on `factory/cli/package-lock.json`
  from the core checkout, so every tarball is checked against its sha512, and it fails closed if the
  `claude_version` input disagrees with the lock. To bump, in one T2 PR: change the version in
  `factory/cli/package.json` and the `claude_version` default in `gate.yml`, then run
  `npm install --package-lock-only` in `factory/cli`. The self-test checks that they match. An adopter
  that overrides `claude_version` without a matching core lock now fails closed.
- **A decoy can satisfy the selftest ratchet.** Moving `--selftest` into a comment escalates,
  but moving it into an unused string does not.
- **Selftest lists are compared by glob, not by content.** The gate has no tree, so any rename
  or delete leaving `selftest_globs` escalates, even for a file with no selftest.
- **Owner approval is only as strong as the owner's token.** An agent session holding that
  login can approve on its behalf. Run sessions under a separate identity.
- **A model BLOCK on T1 or T2 can't be cleared by approval.** It is sticky for that diff. Fix
  the code or use admin bypass.
- **The sticky record is an App review, which write access may be able to alter.** Dismissing
  one doesn't clear it. Whether a write user can edit or delete it isn't verified.
- **Gate data lasts 30 days.** After that, a re-run of `decide` blocks with a clear reason, and
  re-running all jobs or pushing refreshes it.
- **A dismissal binds to one commit.** After the App's approval is dismissed it won't re-approve
  that commit, but a new push gets a new review.
- **Token expiry alert needs one variable per adopting repo.** An expired token fails closed, so
  T1 PRs wait for a person. The review job warns (annotation and job summary) at 14 days or fewer.
  The CLI omits `credential_expires_at` for a token taken from the environment, which is how the
  gate passes it, so the date normally comes from `CLAUDE_TOKEN_EXPIRES_ON` (YYYY-MM-DD, a
  non-secret variable on the `factory-review` environment). Set it whenever you rotate the token:
  `gh variable set CLAUDE_TOKEN_EXPIRES_ON --env factory-review --body YYYY-MM-DD`. The log shows
  `token_days=N token_from=cli|var|none`; `none` means neither source answered, so no alert can fire.
  The date is not secret: it shows in the step's public `env:` block, so it is a plain variable.
  Only `YYYY-MM-DD` is read; anything else counts as unknown.

## alex-factory gates itself

Every file here decides merges for every adopting repo, so the policy is all T2: the gate reviews and tests each PR, and the owner approves it. The App never approves here. The callers in `.github/workflows/factory-gate.yml` and `factory-tests.yml` differ from an adopter's in two ways:
- They call `./.github/workflows/*.yml`.
- They pass `core_sha: base.sha`.

Requirements and limits:
- **`core-v0` must be the default branch.** `pull_request_target` loads the workflow, `./gate.yml` and the environment branch rules from the default branch. On any other branch, the gate never runs and fails closed. Adopters pin by SHA, so changing the default branch doesn't affect them.
- **A PR can't edit its own judge.** The gate loads from the default branch, and the scripts come from `base.sha`.
- **A PR can edit its own tests job.** `factory-tests` runs `pull_request` from the PR's own commit, so a green check on a PR that touches `tests.yml` or `factory-tests.yml` proves nothing. That's acceptable, because everything is T2 and the owner reads the diff.
- **The owner is the only code owner and can't approve their own PRs,** so merges use the admin bypass. The ruleset limits that bypass to PRs (`bypass_mode: pull_request`), so nobody pushes straight to `core-v0`.
- **Factory secrets live only in the two environments**, never at repo level.
