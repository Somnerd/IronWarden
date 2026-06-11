import re

with open("test_suites/test_bridge.py", "r") as f:
    content = f.read()

# Revert wait_for_port since the real issue was WARDEN_MODE wasn't updating properly!
# Wait, let's see why conftest didn't update WARDEN_MODE
