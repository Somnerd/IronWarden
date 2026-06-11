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

# add it after imports
content = re.sub(r'import pytest\nimport os\nimport subprocess\nimport time\nimport requests\nimport jwt', r'import pytest\nimport os\nimport subprocess\nimport time\nimport requests\nimport jwt' + replacement_fixture, content)

# update runner
runner_start = """    def start(self, env_vars=None, **kwargs):
        self.env = os.environ.copy()
        if env_vars:
            self.env.update(env_vars)"""

runner_start_replacement = """    def start(self, env_vars=None, **kwargs):
        self.env = os.environ.copy()
        if env_vars:
            self.env.update(env_vars)

        self.env["WARDEN_ENV"] = "test"
        self.env["WARDEN_MODE"] = "Development"
        self.env["REMOTE_AUDIT_ENDPOINT"] = "http://127.0.0.1:9999/mock-audit"
"""
content = content.replace(runner_start, runner_start_replacement)


# update jwt_factory fixture
jwt_factory_original = """@pytest.fixture
def jwt_factory():
    def _create_jwt(payload):
        # We use symmetric signing for simplicity in tests, using the same secret
        # the Rust server is configured with.
        secret = os.environ.get("JWT_SECRET", "super_secret_test_key_1234567890")
        return jwt.encode(payload, secret, algorithm="HS256")
    return _create_jwt"""

jwt_factory_replacement = """@pytest.fixture
def jwt_factory(jwt_keys):
    def _create_jwt(payload):
        return jwt.encode(payload, jwt_keys["private"], algorithm="RS256")
    return _create_jwt"""

content = content.replace(jwt_factory_original, jwt_factory_replacement)


# in pytest_spawn_rust_server, update environment with jwt keys
# find `runner = IronWardenRunner()` and `runner.start(env_vars={...})`
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

# also fix the argument to pytest_spawn_rust_server
content = content.replace('def pytest_spawn_rust_server():', 'def pytest_spawn_rust_server(jwt_keys):')

with open("test_suites/conftest.py", "w") as f:
    f.write(content)
