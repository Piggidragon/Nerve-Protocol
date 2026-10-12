# Releasing

Releases are made by the `Release` workflow (`.github/workflows/release.yml`),
which the owner starts by hand: **Actions → Release → Run workflow**. Leave
"Use workflow from" on `main` and fill in:

- **branch** (default `main`): the branch to build from.
- **kind**: `pre-release` or `release`.
- **version**: `x.y.z`, the version in the workspace `Cargo.toml`.

## Rules

- A **release** comes from `main` only; any other branch stops the run in its
  first job. Its tag is `v<version>`. If that tag exists, the run fails: tags are
  never moved or reused, so a second release of a version needs a new version.
- A **pre-release** may come from any branch. Its tag is `pre<N>-v<version>`,
  `N` one more than the highest `pre<N>-v<version>` so far (`pre1-v0.0.2` first,
  then `pre2-v0.0.2`). Only for a version that is not released yet: if
  `v<version>` exists the run fails, because a pre-release of it would be
  published after the release, with newer code, under a name that says it is
  older. Once `0.0.1` is released, raise the version on the branch (`0.0.2`)
  before pre-releasing the work after it.
- The version must equal the one in `Cargo.toml`.
- A release needs a `## <version>` section in `CHANGELOG.md`, which becomes its
  release notes. A pre-release uses that section when there is one.
- The run builds the commit the branch is at when it starts, and tags that
  commit in its last job, after the checks and every build passed. A failed run
  leaves no tag and no release: it deletes the draft release and the tag it made
  itself (found by the id and the tag object it recorded, so a draft you wrote
  by hand for the same tag stays), but only when GitHub says the tag has no
  published release. If the last call published the release and only its answer
  was lost, the run is red, the release and its tag stay as they are, and
  nothing needs doing. If GitHub cannot be asked, nothing is deleted and the log
  has a warning: look at **Releases** and **Tags**, and delete a leftover draft
  or tag by hand before you run again.
- One run at a time: a second run waits for the first. While one run waits, a
  third start replaces it (GitHub keeps one waiting run per group).

## What a run does

1. Checks the inputs, the version, the tag and the changelog, then
   `cargo fmt --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`
   and `cargo test --locked --workspace` with the pinned toolchain.
2. Builds `nerve-center` and `nerve-node` for `x86_64-unknown-linux-musl` and
   `aarch64-unknown-linux-musl` (static) and `x86_64-pc-windows-msvc` (static C
   runtime). Each binary must be static (Linux) and print the version from its
   `--version`.
3. Publishes a GitHub Release with the six binaries and `SHA256SUMS`. A release
   is marked latest; a pre-release is marked as a pre-release.

The binaries are not signed: Nerve has no update channel yet. The workflow
uses no secrets; only its last job may write to the repository.

## Before a release

1. Set the version in the workspace `Cargo.toml` (and the `version` of the
   path dependencies in `[workspace.dependencies]`), update `Cargo.lock`
   (`cargo build`), and write the `## <version>` section of `CHANGELOG.md`.
2. Merge that to `main`.
3. Run the workflow with kind `release` and that version.

After a release, raise the version in `Cargo.toml` (and `Cargo.lock`) with the
first change toward the next one; until then the workflow refuses a pre-release
of the released version.
