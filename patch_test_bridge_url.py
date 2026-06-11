import re

with open("test_suites/test_bridge.py", "r") as f:
    content = f.read()

# I see it fails to connect to port 14141. We can wait a little bit for the server to bind the port.
# Also the problem is the server binds to 0.0.0.0:14141.
# Maybe we should wait until the port is open.
content = content.replace('import time', 'import time\nimport socket\n\ndef wait_for_port(port, host="localhost", timeout=5.0):\n    start_time = time.time()\n    while time.time() - start_time < timeout:\n        try:\n            with socket.create_connection((host, port), timeout=1):\n                return True\n        except OSError:\n            time.sleep(0.1)\n    return False')

bridge_url_orig = """@pytest.fixture
def bridge_url(warden):
    port = warden.env["BRIDGE_PORT"]
    return f"http://localhost:{port}\""""

bridge_url_replace = """@pytest.fixture
def bridge_url(warden):
    port = int(warden.env["BRIDGE_PORT"])
    wait_for_port(port)
    return f"http://localhost:{port}\""""

content = content.replace(bridge_url_orig, bridge_url_replace)

with open("test_suites/test_bridge.py", "w") as f:
    f.write(content)
