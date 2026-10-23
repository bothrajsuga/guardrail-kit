# Contributing

Create a focused change with tests and documentation. Install with `pip install -e '.[dev]'`, then run `pytest`, `ruff check .`, and `mypy`. Security fixes should follow `SECURITY.md`, not a public issue.

## TestPyPI release check

1. Update the version and changelog, then run `python -m build` and `twine check dist/*`.
2. Configure a TestPyPI trusted publisher for this repository/environment, or use a short-lived TestPyPI token locally without committing it.
3. Run `python -m twine upload --repository testpypi dist/*` only when authorized.
4. Install into a fresh environment with `pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ guardrail-kit==VERSION` and run import/example smoke tests.
5. Create a GitHub release only after compatibility checks pass. The publish workflow requires that explicit release event and the `pypi` environment. Configure PyPI trusted publishing for the workflow identity before use.

Never place repository or package tokens in source, examples, workflow files, or logs. Re-check distribution-name availability immediately before the first release.

