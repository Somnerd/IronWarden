# Title: [QA] Resolve thread safety race condition in stderr log reader

## Category: QA / Test Infrastructure

## Description
In `test_suites/conftest.py`, the background thread `_read_stderr` reads lines from the gateway process stderr and appends them to the `self.stderr_output` list (see [conftest.py:L136-143](file:///Users/nikolasalexandrakis/Documents/IronWarden/test_suites/conftest.py#L136-L143)). Meanwhile, the main thread reads and iterates over the same list to check for boot indicators:
```python
any("IronWarden Forge ignited" in line for line in self.stderr_output)
```

Iterating over a standard Python list in one thread while another thread is mutating it with `append()` can lead to race conditions and unexpected errors.

We need to make log storage thread-safe.

## Remediation Plan
1. Wrap access to `self.stderr_output` with a `threading.Lock` to synchronize reads and writes.
2. Alternatively, migrate the log collection list to a thread-safe data structure like a `queue.Queue` or `collections.deque` with atomic operations.
