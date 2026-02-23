# Contributing to Invariant

Thanks for contributing.

## Development Setup

1. Install Docker, Go, and Node.js.
2. Start local stack:

```bash
./scripts/bootstrap.sh
```

3. Run the full local quality gate before opening a PR:

```bash
make fmt
make lint
make test
./scripts/check-go-coverage.sh 85.0 coverage_all.out -race
make gosec
make vuln
make trivy
```

## Pull Request Requirements

- Keep behavior deterministic and replayable.
- Do not weaken anti-replay or idempotency controls.
- Add or update tests for every behavior change.
- Keep public APIs backward compatible unless explicitly approved.
- Include migration notes for any unavoidable breaking change.

## Commit and PR Style

- Prefer small, reviewable commits.
- Use clear commit messages (Conventional Commits preferred).
- In PR description include:
  - Problem statement
  - Design choices
  - Test evidence (commands + results)
  - Risk and rollback notes

## Security

- Never commit secrets.
- Report security issues via `SECURITY.md`.
- Keep dependency versions pinned and scan results clean (`0` critical).

