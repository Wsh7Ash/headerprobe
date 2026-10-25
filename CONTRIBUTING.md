# Contributing to headerprobe

Thanks for your interest in improving `headerprobe`.

## Workflow

1. Fork and clone the repository.
2. Create a virtual environment and install: `pip install -e . pytest`
3. Create a feature branch: `git checkout -b fix/my-change`
4. Make your change with tests.
5. Run the gates: `pytest -q` and the demo commands in `docs/USAGE.md`.
6. Open a pull request describing the problem and the fix.

## Guidelines

- **Tests are part of the change.** New behavior needs a test; bug fixes need a
  regression test.
- **Keep the dependency surface small.** Standard library first; adding a runtime
  dependency needs justification in the PR.
- **Keep the exit-code contract** (0/1/2) and `--json-out` stability — CI users
  depend on both.
- **No secrets, ever.** Never commit tokens, keys, or real targets.
- One logical change per PR; write commit messages that explain *why*.

## Reporting bugs

Open an issue with: what you ran, what you expected, what happened, and your
Python/OS versions. For anything security-sensitive, see [SECURITY.md](SECURITY.md).
