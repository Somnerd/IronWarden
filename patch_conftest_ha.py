import re
with open("test_suites/conftest.py", "r") as f:
    content = f.read()

replacement_fixture = """
@pytest.fixture(scope="session")
def jwt_keys():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Extract the public key
    public_key = private_key.public_key()

    # Serialize private key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return {"private": pem_private.decode('utf-8'), "public": pem_public.decode('utf-8')}
"""
content = re.sub(r'import threading\n', r'import threading\n' + replacement_fixture + '\n', content)


runner_start = """    def start(self):
        # Cleanup old files
        if os.path.exists(self.env["AUDIT_DB_PATH"]):
            os.remove(self.env["AUDIT_DB_PATH"])"""

runner_start_replacement = """    def start(self, env_vars=None, **kwargs):
        # We use self.env from __init__ instead of overwriting with os.environ.copy()
        if env_vars:
            self.env.update(env_vars)

        self.env["WARDEN_ENV"] = "test"
        self.env["WARDEN_MODE"] = "hybrid"
        self.env["REMOTE_AUDIT_ENDPOINT"] = "http://127.0.0.1:9999/mock-audit"

        # Cleanup old files
        if "AUDIT_DB_PATH" in self.env and os.path.exists(self.env["AUDIT_DB_PATH"]):
            os.remove(self.env["AUDIT_DB_PATH"])"""
content = content.replace(runner_start, runner_start_replacement)


warden_fixture_orig = """@pytest.fixture
def warden(warden_bin):
    runner = IronWardenRunner(warden_bin)
    runner.start()
    yield runner
    runner.stop()"""

warden_fixture_replacement = """@pytest.fixture
def warden(warden_bin, jwt_keys):
    runner = IronWardenRunner(warden_bin)
    runner.start(env_vars={"JWT_PRIVATE_KEY": jwt_keys["private"], "JWT_PUBLIC_KEY": jwt_keys["public"]})
    yield runner
    runner.stop()"""
content = content.replace(warden_fixture_orig, warden_fixture_replacement)


jwt_factory_orig = """@pytest.fixture
def jwt_factory(warden):
    def _create_token(username):
        secret = warden.env["JWT_SECRET"]
        payload = {
            "sub": username,
            "aud": "test_audience",
            "iss": "test_issuer",
            "exp": int(time.time()) + 3600
        }
        return jwt.encode(payload, secret, algorithm="HS256")
    return _create_token"""

jwt_factory_replacement = """@pytest.fixture
def jwt_factory(jwt_keys):
    import jwt
    def _create_token(username_or_payload):
        if isinstance(username_or_payload, str):
            payload = {
                "sub": username_or_payload,
                "aud": "test_audience",
                "iss": "test_issuer",
                "exp": int(time.time()) + 3600
            }
        else:
            payload = username_or_payload
        return jwt.encode(payload, jwt_keys["private"], algorithm="RS256")
    return _create_token"""
content = content.replace(jwt_factory_orig, jwt_factory_replacement)


# Make sure we add WARDEN_JWT_AUDIENCE to env
content = content.replace('"BRIDGE_PORT": "14141",', '"BRIDGE_PORT": "14141",\n            "WARDEN_JWT_AUDIENCE": "test_audience",\n            "WARDEN_JWT_ISSUER": "test_issuer",')

# and ensure spawn_rust_server gets it
spawn_original = """    runner.start(env_vars={
        "JWT_SECRET": "super_secret_test_key_1234567890",
        "WARDEN_PEPPER": "peppers_should_be_long_enough_32_bytes",
        "BRIDGE_PORT": "14141",
        "RUST_LOG": "info"
    })"""

spawn_replacement = """    runner.start(env_vars={
        "JWT_SECRET": "super_secret_test_key_1234567890",
        "JWT_PRIVATE_KEY": jwt_keys["private"],
        "JWT_PUBLIC_KEY": jwt_keys["public"],
        "WARDEN_PEPPER": "peppers_should_be_long_enough_32_bytes",
        "BRIDGE_PORT": "14141",
        "RUST_LOG": "info"
    })"""
content = content.replace(spawn_original, spawn_replacement)
content = content.replace('def pytest_spawn_rust_server():', 'def pytest_spawn_rust_server(jwt_keys):')

with open("test_suites/conftest.py", "w") as f:
    f.write(content)
