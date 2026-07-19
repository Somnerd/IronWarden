# Title: [QA] Implement dynamic port allocation for integration test runner

## Category: QA / Test Infrastructure

## Description
Currently, the Python integration test runner in `test_suites/conftest.py` hardcodes the gateway bridge port to `"14141"` (see [conftest.py:L77](file:///Users/nikolasalexandrakis/Documents/IronWarden/test_suites/conftest.py#L77)).

If the test suite is run in parallel (using `pytest -n auto`) or in concurrent CI/CD pipeline environments, multiple runner instances will attempt to bind to port `14141` simultaneously, leading to `Address already in use` connection aborts.

We need to implement dynamic port allocation to ensure thread-isolated test runs.

## Remediation Plan
1. Add a helper function in `conftest.py` to find a free local port dynamically:
   ```python
   import socket
   def find_free_port():
       with socket.socket() as s:
           s.bind(('', 0))
           return str(s.getsockname()[1])
   ```
2. Update the `IronWardenRunner` initialization to call this helper and dynamically bind `BRIDGE_PORT` to the returned port.
3. Ensure client tests query the active `runner.env["BRIDGE_PORT"]` rather than using a static URL.
