---
name: prepublish
description: Check a git repo for anything that should not be public before it is made public, published to npm, or pushed to a public remote. Finds private names (clients, employers, internal projects), local home-directory paths, internal scaffolding files, secrets, and the same things in commit messages and old history. Use when the user says "make this repo public", "open source this", "publish this", "is this safe to share", "did I leak anything", or before the first push of a new public repo.
---

# Pre-publish leak check

A public repo publishes three things, and people usually only check the first:

1. **Today's files.** README, source, tests, fixtures, docs, built output.
2. **Commit metadata.** Every commit message and author name and email.
3. **History.** Every old version of every file, downloadable forever from a public repo.

Secrets are only part of it. The common leaks are ordinary words: the client
the tool was built for, an employer, an internal project name, a route copied
from a private codebase, a `/Users/<name>/` path in a test, a planning note an
AI agent left in a comment, or a `.vercel/` folder that got committed.

## Workflow

1. **Build the private-terms list with the user.** Ask what must never appear
   publicly: company and client names, internal project and product names,
   private domains, internal file or route names, colleagues' names. Suggest
   candidates from context (the user's employer, other repos the code was
   extracted from, names in `git log`), but let the user confirm each one.
   Do not add the user's public handle or the repo's own name.
2. **Write the list to `.keysnag-private`** in the repo root, one term per
   line, and make sure `.keysnag-private` is in `.gitignore` before anything
   else. Never put the list in a committed file.
3. **Run the check:**
   ```bash
   npx keysnag scan --checks leaks,secrets --fail-on high --no-osv
   ```
   Read `keysnag.report.md`. Report findings grouped as: current files,
   commit messages, history, tracked scaffolding.
4. **Also look by eye** at what a grep cannot know is private: comments that
   mention internal process ("ledger item", "verify cycle", ticket numbers),
   example values copied from a real product, screenshots, and anything under
   `docs/` or `site/` that belongs somewhere private. Marketing sites, posters
   and internal notes usually belong in a separate private repo.
5. **Fix current files** with generic replacements, rebuild any committed
   build output, run the tests, and commit.
6. **History and commit messages.** If findings remain there:
   - Repo not yet public: rewrite freely (`git filter-repo --replace-text`
     for contents, `--message-callback` for messages), then re-run step 3
     until it is clean.
   - Repo already public: **stop and ask the user.** A rewrite needs a
     force-push, changes every commit hash and tag, breaks existing clones and
     forks, and cannot remove copies GitHub, forks, mirrors or package
     registries already hold. Explain that, get an explicit yes, and rotate
     any real secret first regardless.
7. **Re-run the check** after any rewrite. It is done when the leaks and
   secrets checks report nothing at high or above.

Never print a private term back in a public place (a commit message, a PR
description, an issue) while fixing it. Refer to it as "the private name".
