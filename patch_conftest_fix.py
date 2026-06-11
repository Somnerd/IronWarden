import re

with open("test_suites/conftest.py", "r") as f:
    content = f.read()

runner_start = """    def start(self):
        # Cleanup old files
        if os.path.exists(self.env["AUDIT_DB_PATH"]):
            os.remove(self.env["AUDIT_DB_PATH"])"""

runner_start_replacement = """    def start(self, env_vars=None, **kwargs):
        self.env = os.environ.copy()
        if env_vars:
            self.env.update(env_vars)

        self.env["WARDEN_ENV"] = "test"
        self.env["WARDEN_MODE"] = "Development"
        self.env["REMOTE_AUDIT_ENDPOINT"] = "http://127.0.0.1:9999/mock-audit"

        # Cleanup old files
        if os.path.exists(self.env["AUDIT_DB_PATH"]):
            os.remove(self.env["AUDIT_DB_PATH"])"""

content = content.replace(runner_start, runner_start_replacement)

# some tests might call runner.start() without args, let's fix the start method properly
with open("test_suites/conftest.py", "w") as f:
    f.write(content)
