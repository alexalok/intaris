# Loose-fork upstream workflow

This repository is a **loose fork** of [fpytloun/intaris](https://github.com/fpytloun/intaris).
We expect substantial divergence and treat our fork as a separate product.
Upstream is a source of ideas and selected fixes, not our release authority or
an implementation we must eventually match. Compatibility is a deliberate
choice, not a requirement to adopt every upstream feature or default.

Our maintenance loop is:

1. Review upstream commits since the last completed review checkpoint.
2. Choose useful changes and adapt them through focused backport PRs.
3. Merge the selected PRs and the review record into our fork.
4. Record the reviewed upstream tip with a merge commit that changes no files.

This document defines the process; it does not schedule reviews or authorize
pushes, PR merges, publication, deployment, or live configuration changes.
Follow the worktree ownership protocol below and the applicable user approval
rules for each action.

## Worktree ownership

Before any write (including fetch, tests, builds, installs, or Git changes),
inspect `<worktree-root>/.codex/in-progress`. The marker has a Unix timestamp in
seconds on line 1 and a unique task/session owner ID on line 2. Keep the same ID
through follow-ups. Never stage or commit this marker or its lock files.

A valid timestamp at most 900 seconds old reserves that worktree for its owner;
future timestamps also count as active. An active foreign or unknown owner
requires another worktree; read-only inspection is still allowed. Do not replace
an active foreign marker. An absent, invalid, or expired timestamp permits a
claim, but never permits discarding someone else's uncommitted files.

Serialize claims, refreshes, and deletion using a per-worktree exclusive lock
at `.codex/in-progress.lock`. With that lock held, re-read the marker, check its
owner/expiry, then create it exclusively if absent or atomically replace it if
takeover is permitted. Re-read to verify ownership before each write batch.
Refresh the timestamp before 15 minutes elapse while actively working. If
ownership changes or lock acquisition fails, stop writing and use another
worktree. After a pause, re-check and claim again; do not assume an old claim.

Keep the marker while implementation, verification, review, or requested
follow-up remains unfinished. Do not use an unattended heartbeat. Remove it
only after the changes are committed and the task has no pending work, checking
ownership under the same lock immediately before deletion. Leave uncommitted
work's marker to expire rather than making an unsolicited commit. Ownership
grants no additional staging, push, merge, or deployment permission.

## Product independence

Our source, behavior, versions, builds, artifacts, and deployment configuration
must remain under fork control. An upstream release must not change our product
merely because a tag, package, installer, or remote default changed.

Check each proposed backport for dependencies on upstream-owned resources:

| Surface | Fork requirement |
|---|---|
| Container images | Build our source and use fork-owned image repositories and immutable release identifiers or digests. Never select an upstream product image as our runtime. |
| Packages and client plugins | Build or explicitly maintain compatible versions of our product components. Do not silently install upstream's server or integration package instead of the fork. |
| Installers and downloads | Resolve fork-owned release assets at explicit versions. Avoid scripts that download product code from upstream's current branch or latest release. |
| CI and release workflows | Use our repository, credentials, package destinations, release policy, and validation. Imported workflow assumptions require review. |
| Version discovery | Use our version source and release identifiers. Upstream tags, including tags made ancestral by a checkpoint merge, must not determine our version through an unrestricted `git describe` or similar discovery. |
| Runtime configuration and APIs | Treat upstream service endpoints, schema assumptions, defaults, and compatibility promises as external contracts requiring explicit adoption. |
| Documentation | Identify examples and instructions as fork behavior or upstream reference material. Links to upstream explain provenance; they must not silently drive installation or execution. |

Ordinary third-party dependencies can remain when intentionally selected and
managed. The goal is independence from upstream product artifacts and release
decisions, not replacing every external library. Preserve required license
notices and source attribution when adapting code.

Our product requirements decide acceptance. For example, approving `rm -rf /`
is a hard failure: richer context or a Judge recommendation must not override
that prohibition. An upstream test, benchmark, or default does not supersede
our safety contract.

## Review boundaries and durable records

Use full commit IDs, not dates or release names, as review boundaries:

- **Previous upstream tip:** the upstream commit recorded by the last completed
  checkpoint that is reachable from the fork's current default branch.
- **Reviewed upstream tip:** the exact upstream commit selected for this review.
- **Fork baseline:** the fork default-branch commit used for the assessment.

Freeze the reviewed tip even if upstream advances during the review. Later
commits belong to the next cycle. A report or an unfinished backport branch does
not advance the completed checkpoint.

Create a record at `docs/upstream-reviews/YYYY-MM-DD-<upstream-short-sha>.md`.
Use this structure:

```markdown
# Upstream review YYYY-MM-DD

Status: in progress | ready for checkpoint
Upstream repository: https://github.com/fpytloun/intaris
Previous upstream tip: <full SHA>
Reviewed upstream tip: <full SHA>
Fork baseline: <full SHA>

## Decisions

| Upstream commits / feature | Decision | Reason and adaptation | Fork PR / deferred tracking |
|---|---|---|---|
| <full SHAs and feature> | backport / skip / defer | <reason> | <PR or durable follow-up> |

## Validation

Record tested fork revisions, commands, results, limitations, compatibility
checks, and product-artifact independence checks. Distinguish upstream results
from tests of our adapted implementation.

## Deferred work

Record each deferred item, its original upstream SHAs, why it is deferred, and
the condition for reconsideration. Do not rely on a future commit-range diff
to rediscover it.
```

Account for the entire new range, grouping commits into coherent features when
appropriate. Inspect dependencies on older skipped changes when evaluating a
new patch, but do not reopen all old decisions without a reason. If nothing is
worth taking, a review with only skip/defer decisions can still be completed.
All items selected for backport must be merged before checkpointing; if an item
is dropped or deferred instead, update its decision in the record first.

Keep the deferred list available in subsequent cycles. Checkpoint ancestry will
mark its upstream commits as considered even though their code was not adopted.
Merge the final review record before creating the checkpoint; the checkpoint
itself must not introduce or edit that record.

## Inspect only the new upstream range

Resolve remotes by repository URL. Do not assume `origin` is our fork: existing
checkouts may use `origin` for upstream. Examples below use `upstream` for
`fpytloun/intaris` and `fork` for `alexalok/intaris`; substitute verified aliases.
Do not change remote configuration or pull upstream into the fork implicitly.

After claiming the worktree, fetch the two default branches and record their
exact tips. Avoid importing upstream tags into our release namespace as a side
effect of review. Use `--no-tags` and explicit branch refspecs for both fetches;
this also avoids relying on a remote's configured fetch refspecs. Replace every
placeholder, then run the complete block as one command. Its subshell stops on
failure without changing the caller's shell options. Record the printed commit
IDs before inspecting the range:

```bash
(
set -eu
# Replace these aliases/default branches with the verified repository values.
upstream_remote=upstream
upstream_branch=main
fork_remote=fork
fork_branch=main
last_reviewed=<previous-upstream-full-sha>

git fetch --no-tags "$upstream_remote" \
  "refs/heads/$upstream_branch:refs/remotes/$upstream_remote/$upstream_branch"
git fetch --no-tags "$fork_remote" \
  "refs/heads/$fork_branch:refs/remotes/$fork_remote/$fork_branch"
reviewed_upstream=$(git rev-parse "refs/remotes/$upstream_remote/$upstream_branch^{commit}")
fork_baseline=$(git rev-parse "refs/remotes/$fork_remote/$fork_branch^{commit}")

boundary_fork=$fork_baseline
# Continuation: use the last completed checkpoint reachable from this fork tip.
# First cycle only: set review_mode=first-cycle and previous_checkpoint=none.
review_mode=continuation
previous_checkpoint=<last-checkpoint-full-sha>
if [ "$review_mode" = first-cycle ]; then
  test "$previous_checkpoint" = none
  test -z "$(git log --merges --format=%H --grep='^Upstream-Reviewed: ' "$boundary_fork")"
  test "$(git merge-base "$boundary_fork" "$reviewed_upstream")" = "$last_reviewed"
elif [ "$review_mode" = continuation ]; then
  test "$(git rev-parse "$previous_checkpoint^{commit}")" = "$previous_checkpoint"
  git merge-base --is-ancestor "$previous_checkpoint" "$boundary_fork"
  recorded_tip=$(git show -s --format='%(trailers:key=Upstream-Reviewed,valueonly)' "$previous_checkpoint")
  test "$recorded_tip" = "$last_reviewed"
  previous_first=$(git rev-parse "$previous_checkpoint^1")
  test "$(git show -s --format=%P "$previous_checkpoint")" = "$previous_first $recorded_tip"
  test "$(git rev-parse "$previous_checkpoint^{tree}")" = "$(git rev-parse "$previous_first^{tree}")"
  previous_record=$(git show -s --format='%(trailers:key=Upstream-Review-Record,valueonly)' "$previous_checkpoint")
  test -n "$previous_record"
  test "$(git cat-file -t "$previous_first:$previous_record")" = blob
  previous_contents=$(git show "$previous_first:$previous_record")
  test "$(printf '%s\n' "$previous_contents" | grep '^Status: ')" = 'Status: ready for checkpoint'
  test "$(printf '%s\n' "$previous_contents" | grep '^Reviewed upstream tip: ')" = "Reviewed upstream tip: $recorded_tip"
else
  printf '%s\n' 'Unknown review mode; stop.' >&2
  exit 1
fi

if ! git merge-base --is-ancestor "$last_reviewed" "$reviewed_upstream"; then
  printf '%s\n' 'Upstream ancestry mismatch; stop and investigate the review boundary.' >&2
  exit 1
fi
printf 'Previous upstream: %s\nReviewed upstream: %s\nFork baseline: %s\n' \
  "$last_reviewed" "$reviewed_upstream" "$fork_baseline"
git log --reverse --topo-order --format='%H %s' --patch --diff-merges=separate "$last_reviewed..$reviewed_upstream"
git diff --stat "$last_reviewed" "$reviewed_upstream"
git diff "$last_reviewed" "$reviewed_upstream" -- <paths-under-review>
)
```

Stop and investigate if the ancestry check fails; do not silently replace the
baseline after upstream rewrites history. For the first cycle with no checkpoint,
establish and record a verified common ancestor as the starting point. Do not
treat an informal previous conversation or a checkout's stale tracking ref as a
completed checkpoint. The complete recipes require an explicit `first-cycle`
mode for that case and reject it when checkpoint trailers already exist.
For continuation, set the last checkpoint's full commit ID; both recipes verify
its upstream trailer, reachability, ordered parents, unchanged tree, and linked
committed review record before accepting the previous tip. Select the latest
completed checkpoint using ancestry; if competing checkpoint histories exist,
stop and reconcile them explicitly rather than choosing by date.

Per-commit patches include intermediate changes and reverts even when endpoint
trees match. Endpoint diffs provide an additional aggregate view only.

To find prior checkpoint candidates, inspect merge commits reachable from the
fork branch with the `Upstream-Reviewed` trailer. Validate each candidate's two
parents, unchanged tree, recorded upstream SHA, and linked review record. Do not
rely only on a commit subject or timestamp. The relevant checkpoint may be an
ancestor behind a PR merge, rather than directly on the first-parent chain.

## Adapt through backport PRs

Start each backport from current fork main in an owned worktree. Keep PRs focused
on a coherent behavior change, including its tests and necessary dependencies.
When one upstream commit contains many unrelated changes, extract only the
selected unit; do not cherry-pick the whole release for convenience.

Each PR should explain the problem, intended fork behavior, original upstream
SHAs, deliberate deviations, related review record, and validation. Test the
adapted implementation against our existing contracts and affected clients.
Upstream CI or benchmark results do not qualify our changed version. Follow our
normal PR review and merge rules; do not weaken tests to make the import pass.

Backport PRs may use the fork's normal merge method. The checkpoint below is
different: its upstream parent must survive integration into fork main.

## Record the completed review without importing code

The checkpoint is a real **two-parent merge with an unchanged tree**:

- First parent: current fork main, after all selected backports and the review
  record have merged.
- Second parent: the frozen reviewed upstream tip.
- Tree: exactly the first parent's tree.

It means “reviewed through this upstream commit; dispositions are documented.”
It does not mean all upstream changes are present or that the fork matches that
upstream release. Git will nevertheless treat that upstream history as merged.
Future work must continue to use selective backports and consult deferred items;
a later ordinary merge will not bring back old skipped changes automatically.

Use Git's `ours` **strategy** (`-s ours`), which retains the complete current
tree. Do not substitute `-X ours`, which can import non-conflicting changes, or
`git commit --allow-empty`, which does not record the upstream parent.

The following is a manual recipe for an authorized checkpoint operation. Start
from a clean, claimed worktree at verified current fork main. Exclude the local
coordination marker from commits. Replace every placeholder and verify the fork
remote/default branch, then run the complete subshell block. `set -eu` makes a
failed fetch, metadata check, merge, or assertion stop before later commands.
The preflight requires a clean tracked worktree/index at freshly fetched fork
main and a committed review record with exactly one matching status and each
boundary field, including the full fork baseline SHA saved at review start.
That baseline must resolve to a commit and be an ancestor of current fork main.
A local untracked record cannot satisfy these checks.

```bash
(
set -eu
reviewed_upstream=<reviewed-upstream-full-sha>
last_reviewed=<previous-upstream-full-sha>
review_record=docs/upstream-reviews/<review-file>.md
fork_baseline=<reviewed-fork-baseline-full-sha>
fork_remote=fork
fork_branch=main

git fetch --no-tags "$fork_remote" \
  "refs/heads/$fork_branch:refs/remotes/$fork_remote/$fork_branch"
fork_before=$(git rev-parse "refs/remotes/$fork_remote/$fork_branch^{commit}")
boundary_fork=$fork_before
# Continuation: use the last completed checkpoint reachable from this fork tip.
# First cycle only: set review_mode=first-cycle and previous_checkpoint=none.
review_mode=continuation
previous_checkpoint=<last-checkpoint-full-sha>
if [ "$review_mode" = first-cycle ]; then
  test "$previous_checkpoint" = none
  test -z "$(git log --merges --format=%H --grep='^Upstream-Reviewed: ' "$boundary_fork")"
  test "$(git merge-base "$boundary_fork" "$reviewed_upstream")" = "$last_reviewed"
elif [ "$review_mode" = continuation ]; then
  test "$(git rev-parse "$previous_checkpoint^{commit}")" = "$previous_checkpoint"
  git merge-base --is-ancestor "$previous_checkpoint" "$boundary_fork"
  recorded_tip=$(git show -s --format='%(trailers:key=Upstream-Reviewed,valueonly)' "$previous_checkpoint")
  test "$recorded_tip" = "$last_reviewed"
  previous_first=$(git rev-parse "$previous_checkpoint^1")
  test "$(git show -s --format=%P "$previous_checkpoint")" = "$previous_first $recorded_tip"
  test "$(git rev-parse "$previous_checkpoint^{tree}")" = "$(git rev-parse "$previous_first^{tree}")"
  previous_record=$(git show -s --format='%(trailers:key=Upstream-Review-Record,valueonly)' "$previous_checkpoint")
  test -n "$previous_record"
  test "$(git cat-file -t "$previous_first:$previous_record")" = blob
  previous_contents=$(git show "$previous_first:$previous_record")
  test "$(printf '%s\n' "$previous_contents" | grep '^Status: ')" = 'Status: ready for checkpoint'
  test "$(printf '%s\n' "$previous_contents" | grep '^Reviewed upstream tip: ')" = "Reviewed upstream tip: $recorded_tip"
else
  printf '%s\n' 'Unknown review mode; stop.' >&2
  exit 1
fi
test "$(git rev-parse HEAD)" = "$fork_before"
fork_tree=$(git rev-parse 'HEAD^{tree}')
git diff --exit-code
git diff --cached --exit-code
# Use the full fork baseline recorded when the review started, not current HEAD.
test "$(git rev-parse "$fork_baseline^{commit}")" = "$fork_baseline"
git merge-base --is-ancestor "$fork_baseline" "$fork_before"

# Read committed metadata, never an untracked or modified working-copy record.
test "$(git cat-file -t "$fork_before:$review_record")" = blob
record_contents=$(git show "$fork_before:$review_record")
test "$(printf '%s\n' "$record_contents" | grep '^Status: ')" = 'Status: ready for checkpoint'
test "$(printf '%s\n' "$record_contents" | grep '^Previous upstream tip: ')" = "Previous upstream tip: $last_reviewed"
test "$(printf '%s\n' "$record_contents" | grep '^Reviewed upstream tip: ')" = "Reviewed upstream tip: $reviewed_upstream"
test "$(printf '%s\n' "$record_contents" | grep '^Fork baseline: ')" = "Fork baseline: $fork_baseline"
if ! git merge-base --is-ancestor "$last_reviewed" "$reviewed_upstream"; then
  printf '%s\n' 'Upstream ancestry mismatch; no checkpoint may be created.' >&2
  exit 1
fi

git merge --no-ff --no-commit -s ours "$reviewed_upstream"
test "$(git rev-parse MERGE_HEAD)" = "$reviewed_upstream"
test "$(git write-tree)" = "$fork_tree"
git diff --exit-code
git diff --cached --exit-code

git commit \
  -m "chore(upstream): record review through ${reviewed_upstream:0:12}" \
  -m "Upstream-Reviewed: $reviewed_upstream
Upstream-Previous: $last_reviewed
Upstream-Review-Record: $review_record"

checkpoint=$(git rev-parse HEAD)
test "$(git show -s --format=%P HEAD)" = "$fork_before $reviewed_upstream"
test "$(git rev-parse 'HEAD^{tree}')" = "$fork_tree"
git rev-list --parents -n 1 HEAD
git diff --exit-code HEAD^1 HEAD --
)
```

Require exactly two parents. If the tip is already an ancestor and Git reports
that nothing needs merging, verify the existing checkpoint instead of inventing
another one. If any check fails, stop; do not commit an apparent checkpoint.
If a failure occurs after the merge starts, inspect the remaining merge state
before deciding how to recover; never continue with the commit command alone.

Publish/integrate the checkpoint only through an explicitly authorized path
that **preserves the merge commit and its two parents**. A merge-commit PR can
preserve it if repository rules and the hosting UI support the zero-file-diff
case. Squash merge or rebase-and-merge cannot serve as this checkpoint. If a
history-only PR is unsupported or branch rules prohibit merge commits, report
the constraint and obtain an authorized compatible path; do not bypass rules
or pretend an empty one-parent commit is equivalent. Direct main updates are
not implicitly authorized by this procedure.

After integration, verify that the checkpoint is reachable from freshly fetched
fork main and that its tree still equals its first parent's tree. If fork main
advanced while the checkpoint was prepared, preserve those newer changes and
check that integrating the checkpoint introduced no file changes relative to
the receiving branch. Do not force-push or rewrite published checkpoints.

Next review starts at the recorded `Upstream-Reviewed` SHA, while also checking
the deferred-work list. Push-triggered CI may still run on a checkpoint even
though its file tree is unchanged; normal publication and deployment controls
continue to apply.

## References

- [Git merge strategies](https://git-scm.com/docs/merge-strategies)
- [Git merge options](https://git-scm.com/docs/git-merge)
- [GitHub merge methods](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/about-merge-methods-on-github)
