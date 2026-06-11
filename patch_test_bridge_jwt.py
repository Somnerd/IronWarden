import re

with open("test_suites/test_bridge.py", "r") as f:
    content = f.read()

# I see AttributeError: module 'jwt' has no attribute 'encode'
# Wait! I removed `import jwt` or something in conftest.py or test_bridge.py?
# test_bridge.py has `import jwt`, maybe I pip installed the wrong `jwt`?
# PyJWT is the correct one, let's `pip install PyJWT` and try.
