import re

with open("test_suites/conftest.py", "r") as f:
    content = f.read()

# Let's see if there is a random port assigned.
# Also let's output stderr on failure so we can debug test_bridge_health
