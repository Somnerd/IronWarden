import subprocess
import os
import time
import requests

from test_suites.jwt_keys import PUBLIC_KEY, PRIVATE_KEY

env = os.environ.copy()
env.update({
    "WARDEN_MODE": "ephemeral",
    "WARDEN_PEPPER": "a_very_secret_pepper_32_bytes_long",
    "OPENAI_API_KEY": "sk-mock-key",
    "JWT_SECRET": "another_very_secret_key_32_bytes_long",
    "JWT_PRIVATE_KEY": PRIVATE_KEY,
    "JWT_PUBLIC_KEY": PUBLIC_KEY,
    "DISABLE_HA_CHECK": "1",
    "WARDEN_JWT_AUDIENCE": "test_audience",
    "WARDEN_JWT_ISSUER": "test_issuer",
    "DATABASE_URL": "postgres://somnerd:postgres@localhost:5432/ironwarden",
    "REDIS_URL": "redis://localhost:6379",
    "AUDIT_DB_PATH": "test_audit.db",
    "LANCEDB_PATH": "test_lancedb",
    "WARDEN_CONFIG_PATH": "config/regions",
    "BRIDGE_PORT": "14141",
    "LOG_FORMAT": "text",
})

p = subprocess.Popen(["./target/debug/app"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

time.sleep(3)
try:
    print(requests.get("http://localhost:14141/health").status_code)
except Exception as e:
    print(e)
p.kill()
stdout, stderr = p.communicate()
print("STDOUT:", stdout)
print("STDERR:", stderr)
