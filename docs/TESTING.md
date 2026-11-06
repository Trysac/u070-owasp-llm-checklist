# Testing

## Running

```sh
uv run pytest --cov=owasp_llm_checklist   # tests with coverage report
uv run python scripts/check.py            # every gate, as CI runs it
```

## Policy

- Branch coverage of `src/owasp_llm_checklist` must stay at or above 80 %; the gate fails below it.
- Tests exercise the public API (`import owasp_llm_checklist`) and the CLI, asserting return values, raised exceptions, messages and exit codes.
- Each bug fix starts with a failing test that reproduces it.
- Tests are deterministic: no network, no wall clock, no dependence on test order.

## Layout

`tests/test_<module>.py` mirrors each public module. Shared fixtures go in `tests/conftest.py`.

The acceptance cases the tests must cover are: rule set shape and question risk ids; the `P01` finding and its inline `# owasp-llm: ignore P01` silencing; secret masking in both formats; scanner exclusions, NUL-byte skipping, size limit and symlinks; the 4096-character line limit and `max_findings` truncation; the four risk states; answers validation errors; and the `--fail-on-open` exit codes.
