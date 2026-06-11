import re

with open("test_suites/test_adversarial.py", "r") as f:
    content = f.read()

# Replace hardcoded JWT test tokens
content = re.sub(r'secret = warden.env\["JWT_SECRET"\]\s+token = jwt.encode\(.*?, secret, algorithm="HS256"\)',
                 r'token = jwt.encode({"sub": "tester", "aud": "test_audience", "iss": "test_issuer", "exp": int(time.time()) + 3600}, warden.env["JWT_PRIVATE_KEY"], algorithm="RS256")', content)

with open("test_suites/test_adversarial.py", "w") as f:
    f.write(content)
