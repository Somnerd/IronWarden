import re
with open("test_suites/conftest.py", "r") as f:
    content = f.read()

# Replace jwt_keys fixture to return statically defined keys
content = re.sub(r'@pytest\.fixture\(scope="session"\)\ndef jwt_keys\(\):\n(?:.|\n)*?return \{"private": pem_private\.decode\(\'utf-8\'\), "public": pem_public\.decode\(\'utf-8\'\)\}',
                 """import sys\nimport os\nsys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))\nfrom jwt_keys import PUBLIC_KEY, PRIVATE_KEY\n\n@pytest.fixture(scope="session")\ndef jwt_keys():\n    return {"private": PRIVATE_KEY, "public": PUBLIC_KEY}""",
                 content)

with open("test_suites/conftest.py", "w") as f:
    f.write(content)
