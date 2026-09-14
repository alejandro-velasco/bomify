## Summary

<!-- What does this change do, and why? -->

## Related issues

<!--
Link any related GitHub issues, if they exist. Use a closing keyword (Closes/Fixes/Resolves)
to auto-close the issue when this PR merges, or "Relates to" if it's related but shouldn't
close it, e.g.:

Closes #123
Relates to #456

Leave this section empty (or remove it) if there's no related issue.
-->

## Type of change

<!-- Pick one; this drives the release semver-release computes from your commits. -->

- [ ] `feat` — a new feature (minor release)
- [ ] `fix` — a bug fix (patch release)
- [ ] `docs` — documentation only
- [ ] `refactor` — code change that neither fixes a bug nor adds a feature
- [ ] `perf` — a performance improvement
- [ ] `test` — adding or correcting tests
- [ ] `build` / `ci` — build system or CI/CD changes
- [ ] `chore` — anything else that doesn't modify source or test files

## Conventional Commits

This repo's releases are cut by [semantic-release](https://semantic-release.gitbook.io/) directly from commit
messages on `main`, so **every commit in this PR** (not just the PR title) must follow
[Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

- [ ] Every commit message follows the `<type>[(scope)]: <description>` format
- [ ] A breaking change is flagged with `!` after the type/scope (e.g. `feat!:`) or a `BREAKING CHANGE:` footer
- [ ] Commit descriptions are lowercase, imperative mood, no trailing period (e.g. `fix: correct pull retry logic`)

## Test plan

<!-- How was this verified? -->
