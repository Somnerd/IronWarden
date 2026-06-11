import re

with open("test_suites/test_bridge.py", "r") as f:
    content = f.read()

content = content.replace('assert response.status_code == 200', 'try:\n        assert response.status_code == 200\n    except Exception as e:\n        print(f"FAILED WITH {response.text}")\n        raise e')

with open("test_suites/test_bridge.py", "w") as f:
    f.write(content)
