# Repository Development Guidelines

## 1. Branching & Gitflow Standards
- **Active Branch**: All work must be conducted on feature or fix branches branched exclusively from `dev` (e.g., `fix/ci-pytest-timeout`).
- **Target Branch**: All Pull Requests must target `dev`. NEVER open a PR directly against `main`.
- **Protected Main**: `main` is only updated via fast-forward or release merges from `dev` upon Nikolas's request.

## 2. Local Verification Checklist (Pre-PR)
Before pushing commits or opening PRs:
1. `cargo fmt --all -- --check` must return 0.
2. `cargo clippy --workspace --all-targets -- -D warnings` must return 0.
3. Tests must pass locally: `pytest test_suites/ -k "not stress and not benchmark"`.
