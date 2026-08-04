# Title: [QA] Implement temporary database cleanup on test teardown

## Category: QA / Test Infrastructure

## Description
The integration test runner creates temporary SQLite database files (`test_audit_*.db`) and LanceDB directory directories (`test_lancedb_*`) in the project root to isolate test sessions (see [conftest.py:L74-75](file:///Users/nikolasalexandrakis/Documents/IronWarden/test_suites/conftest.py#L74-L75)).

While the runner attempts to delete existing files on startup, it fails to clean up these files during test teardown. Running the test suite leaves multiple orphan `.db` files and directories cluttering the workspace.

We need to implement a clean teardown flush.

## Remediation Plan
1. Update `stop(self)` in `test_suites/conftest.py` to automatically delete `AUDIT_DB_PATH` and the LanceDB directory on successful termination.
2. Alternatively, configure the test runner to use `tempfile.TemporaryDirectory` for transient storage, ensuring the host system removes them automatically on process exit.
