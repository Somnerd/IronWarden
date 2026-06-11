import re

with open("test_suites/test_bridge.py", "r") as f:
    content = f.read()

# I see test_bridge_health fails with JSON decode error, which means it received text. Let's see what it received.
content = content.replace('assert response.json()["status"] == "healthy"', 'try:\n        assert response.json()["status"] == "healthy"\n    except Exception as e:\n        print(f"FAILED WITH {response.text}")\n        raise e')

with open("test_suites/test_bridge.py", "w") as f:
    f.write(content)
