"""
Pytest configuration and shared fixtures for the IronWarden test suite.
Provides Runner helpers for managing the gateway subprocess, environment variables,
RSA/JWT keys generation, database paths, and JSON-RPC Model Context Protocol (MCP) clients.
"""
import pytest
import subprocess
import json
import time
import os
import signal
import threading

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


class IronWardenRunner:
    def __init__(self, bin_path, env_overrides=None):
        self.bin_path = bin_path
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        unique_id = f"{int(time.time() * 1000)}"
        
        # Locate libtorch for runtime loading
        ld_library_path = os.environ.get("LD_LIBRARY_PATH", "")
        ld_preload = os.environ.get("LD_PRELOAD", "")
        import glob
        torch_lib_dirs = glob.glob(os.path.join(project_root, "target/debug/build/torch-sys-*/out/libtorch/libtorch/lib"))
        if torch_lib_dirs:
            # Sort by modification time to get the latest
            torch_lib_dirs.sort(key=os.path.getmtime, reverse=True)
            latest_lib_dir = torch_lib_dirs[0]
            ld_library_path = f"{latest_lib_dir}:{ld_library_path}"
            
            # Preload libc10 to fix symbol lookup errors
            libc10 = os.path.join(latest_lib_dir, "libc10.so")
            if os.path.exists(libc10):
                ld_preload = f"{libc10}:{ld_preload}"

        # Generate default JWT keys if not provided in overrides
        if not env_overrides or "JWT_PUBLIC_KEY" not in env_overrides:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            pem_private = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            pem_public = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        else:
            pem_private = env_overrides.get("JWT_PRIVATE_KEY", "")
            pem_public = env_overrides.get("JWT_PUBLIC_KEY", "")

        import socket
        def get_free_port():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', 0))
                return s.getsockname()[1]

        base_env = {
            **os.environ,
            "WARDEN_MODE": "ephemeral",
            "WARDEN_PEPPER": "this-is-a-valid-32-byte-test-pepper-string!",
            "OPENAI_API_KEY": "sk-mock-key",
            "JWT_SECRET": "another_very_secret_key_32_bytes_long",
            "JWT_PRIVATE_KEY": pem_private,
            "JWT_PUBLIC_KEY": pem_public,
            "DATABASE_URL": "postgres://somnerd:postgres@localhost:5432/ironwarden",
            "REDIS_URL": "redis://localhost:6379",
            "AUDIT_DB_PATH": os.path.join(project_root, f"test_audit_{unique_id}.db"),
            "LANCEDB_PATH": os.path.join(project_root, f"test_lancedb_{unique_id}"),
            "WARDEN_CONFIG_PATH": os.path.join(project_root, "config/rules"),
            "WARDEN_JWT_AUDIENCE": "test_audience",
            "WARDEN_JWT_ISSUER": "test_issuer",
            "LOG_FORMAT": "text",
            "LD_LIBRARY_PATH": ld_library_path,
            "LD_PRELOAD": ld_preload,
        }
        
        # Override values before resolving defaults
        merged_env = {**base_env, **(env_overrides or {})}
        
        # Use dynamic port if not specified in overrides
        if "BRIDGE_PORT" not in merged_env:
            merged_env["BRIDGE_PORT"] = str(get_free_port())
            
        self.env = merged_env
        self.process = None
        self.stderr_output = []
        self.stderr_lock = threading.Lock()

        # Initial clean up of old files
        if "AUDIT_DB_PATH" in self.env and os.path.exists(self.env["AUDIT_DB_PATH"]):
            try:
                os.remove(self.env["AUDIT_DB_PATH"])
            except Exception:
                pass


    def start(self, env_vars=None, **kwargs):
        # We use self.env from __init__ instead of overwriting with os.environ.copy()
        if env_vars:
            self.env.update(env_vars)

        self.env["WARDEN_ENV"] = "test"
        self.env["WARDEN_MODE"] = "hybrid"
        self.env["REMOTE_AUDIT_ENDPOINT"] = "http://127.0.0.1:9999/mock-audit"
        self.env["WARDEN_MCP_SECRET"] = "test_secret_32_bytes_minimum_length!"
        self.env.setdefault("WARDEN_PEPPER", "this-is-a-valid-32-byte-test-pepper-string!")

        # Generate temporary manifest mapping rules_dir to WARDEN_CONFIG_PATH for tests
        if "WARDEN_CONFIG_PATH" in self.env:
            config_dir = self.env["WARDEN_CONFIG_PATH"]
            import yaml
            import tempfile
            
            project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            # Read original active_rules if they exist to prevent breaking regional tests
            original_manifest_path = os.path.join(project_root, "config/manifest.yaml")
            active_rules = ["rules.yaml"]
            if "WARDEN_ACTIVE_RULES" in self.env:
                active_rules = [self.env["WARDEN_ACTIVE_RULES"]]
            elif os.path.exists(original_manifest_path):
                try:
                    with open(original_manifest_path, "r") as f:
                        orig = yaml.safe_load(f)
                        if orig and "active_rules" in orig:
                            active_rules = [
                                r for r in orig["active_rules"]
                                if os.path.exists(os.path.join(config_dir, r))
                            ]
                            if not active_rules:
                                active_rules = ["rules.yaml"]
                except Exception:
                    pass
            
            manifest_content = {
                "rules_dir": config_dir,
                "active_rules": active_rules
            }
            temp_manifest = tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w")
            yaml.dump(manifest_content, temp_manifest)
            temp_manifest.close()
            self.env["WARDEN_MANIFEST_PATH"] = temp_manifest.name
            self._temp_manifest_path = temp_manifest.name
        else:
            self._temp_manifest_path = None



        self.process = subprocess.Popen(
            [self.bin_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=self.env
        )
        
        # Start stderr reader thread
        self.stop_event = threading.Event()
        self.stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self.stderr_thread.start()
        
        # Wait for "IronWarden Forge ignited" in stderr or just timeout
        start_time = time.time()
        ignited = False
        while time.time() - start_time < 30:
            current_stderr = self.get_stderr_output()
            if any("IronWarden Forge ignited" in line for line in current_stderr):
                ignited = True
                break
            if self.process.poll() is not None:
                stderr = "\n".join(self.get_stderr_output())
                raise RuntimeError(f"IronWarden failed to start. Exit code: {self.process.returncode}\nStderr: {stderr}")
            time.sleep(0.1)

        if not ignited:
             stderr = "\n".join(self.get_stderr_output())
             self.stop()
             raise RuntimeError(f"IronWarden timed out starting. Stderr:\n{stderr}")
        
        # Settle delay to ensure background DB tasks are fully committed
        time.sleep(1)

    def get_stderr_output(self):
        with self.stderr_lock:
            return list(self.stderr_output)

    def _read_stderr(self):
        while not self.stop_event.is_set():
            line = self.process.stderr.readline()
            if not line:
                break
            line = line.strip()
            with self.stderr_lock:
                self.stderr_output.append(line)
            print(f"DEBUG LOG: {line}")

    def stop(self, cleanup=False):
        if self.process:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.stop_event.set()

        if cleanup:
            # Cleanup temporary resources
            try:
                if hasattr(self, "_temp_manifest_path") and self._temp_manifest_path and os.path.exists(self._temp_manifest_path):
                    os.remove(self._temp_manifest_path)

                if "AUDIT_DB_PATH" in self.env and os.path.exists(self.env["AUDIT_DB_PATH"]):
                    os.remove(self.env["AUDIT_DB_PATH"])
                    # Also remove WAL/SHM files
                    for ext in ["-shm", "-wal", ".anchor"]:
                        if os.path.exists(self.env["AUDIT_DB_PATH"] + ext):
                            os.remove(self.env["AUDIT_DB_PATH"] + ext)

                if "LANCEDB_PATH" in self.env and os.path.exists(self.env["LANCEDB_PATH"]):
                    import shutil
                    shutil.rmtree(self.env["LANCEDB_PATH"], ignore_errors=True)
            except Exception as e:
                print(f"DEBUG: Cleanup failed: {e}")

    def send_mcp(self, method, params, request_id=1):
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": request_id
        }
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()

        # Read until we get a JSON-RPC response, skipping logs
        start_time = time.time()
        while time.time() - start_time < 10:
            line = self.process.stdout.readline()
            if not line:
                print(f"DEBUG: MCP Stdout EOF reached while waiting for {method}")
                return None
            line = line.strip()
            if not line:
                continue

            # Basic heuristic: if it starts with { it might be our response
            if line.startswith('{"jsonrpc"'):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    print(f"DEBUG: Failed to parse JSON-RPC line: {line}")
                    continue
            else:
                # Likely a log line or other output, keep looking
                if "DEBUG" not in line: # Avoid double logging our own debugs
                    print(f"DEBUG OUT: {line}")

        print(f"DEBUG: MCP Timeout waiting for {method}")
        return None

@pytest.fixture(scope="session")
def warden_bin():
    # Ensure binary is built
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    subprocess.run(["cargo", "build", "-p", "app"], cwd=project_root, check=True)
    return os.path.join(project_root, "target", "debug", "app")

@pytest.fixture
def warden(warden_bin, jwt_keys):
    runner = IronWardenRunner(warden_bin)
    runner.start(env_vars={"JWT_PRIVATE_KEY": jwt_keys["private"], "JWT_PUBLIC_KEY": jwt_keys["public"]})
    yield runner
    runner.stop(cleanup=True)

@pytest.fixture
def jwt_factory(warden):
    import jwt
    def _create_token(username, roles=None):
        if roles is None:
            roles = ["admin"]
        private_key = warden.env["JWT_PRIVATE_KEY"]
        payload = {
            "sub": username,
            "exp": int(time.time()) + 3600,
            "roles": roles,
            "aud": warden.env.get("WARDEN_JWT_AUDIENCE", "test_audience"),
            "iss": warden.env.get("WARDEN_JWT_ISSUER", "test_issuer"),
        }
        return jwt.encode(payload, private_key, algorithm="RS256")
    return _create_token


@pytest.fixture(scope="session")
def warden_factory(warden_bin, jwt_keys):
    """
    Session-scoped factory fixture that creates IronWardenRunner instances
    with custom environment overrides. Used by proxy tests to point IronWarden
    at a mock upstream LLM server.

    Usage:
        def test_something(warden_factory, mock_upstream):
            runner = warden_factory(env_overrides={"OPENAI_BASE_URL": mock_upstream.base_url()})
            runner.start()
            yield runner
            runner.stop()
    """
    runners = []

    def _factory(env_overrides=None):
        overrides = {
            "JWT_PRIVATE_KEY": jwt_keys["private"],
            "JWT_PUBLIC_KEY": jwt_keys["public"],
            **(env_overrides or {}),
        }
        runner = IronWardenRunner(warden_bin, env_overrides=overrides)
        runners.append(runner)
        return runner

    yield _factory

    # Cleanup all runners created by this factory
    for runner in runners:
        try:
            runner.stop(cleanup=True)
        except Exception:
            pass


# ── Proxy-specific fixtures ───────────────────────────────────────────────────

@pytest.fixture(scope="module")
def proxy_warden(warden_bin, jwt_keys, mock_upstream):
    """
    Module-scoped IronWarden instance for proxy integration tests.
    Exposes runner.env so tests can access AUDIT_DB_PATH, JWT_PRIVATE_KEY, etc.
    Pointed at mock_upstream via OPENAI_BASE_URL and ANTHROPIC_BASE_URL.
    """
    overrides = {
        "JWT_PRIVATE_KEY": jwt_keys["private"],
        "JWT_PUBLIC_KEY": jwt_keys["public"],
        "OPENAI_BASE_URL": f"{mock_upstream.base_url()}/v1/chat/completions",
        "ANTHROPIC_BASE_URL": f"{mock_upstream.base_url()}/v1/messages",
    }
    runner = IronWardenRunner(warden_bin, env_overrides=overrides)
    runner.start()
    yield runner
    runner.stop(cleanup=True)


@pytest.fixture(scope="module")
def proxy_url(proxy_warden):
    """Base URL of the proxy_warden instance."""
    port = proxy_warden.env["BRIDGE_PORT"]
    return f"http://127.0.0.1:{port}"


@pytest.fixture(scope="module")
def blocked_warden(warden_bin, jwt_keys, mock_upstream):
    """
    Module-scoped IronWarden instance configured with the block-test rules file.
    The rules_block_test.yaml adds an explicit Block action on the sentinel
    keyword 'IRONWARDEN_BLOCK_THIS', used by hard-block security tests to
    guarantee that a policy-blocked prompt never reaches the upstream.
    """
    import os
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    block_rules_dir = os.path.join(project_root, "config", "rules")

    overrides = {
        "JWT_PRIVATE_KEY": jwt_keys["private"],
        "JWT_PUBLIC_KEY": jwt_keys["public"],
        "OPENAI_BASE_URL": f"{mock_upstream.base_url()}/v1/chat/completions",
        "ANTHROPIC_BASE_URL": f"{mock_upstream.base_url()}/v1/messages",
        "WARDEN_CONFIG_PATH": block_rules_dir,
        "WARDEN_ACTIVE_RULES": "rules_block_test.yaml",
    }
    runner = IronWardenRunner(warden_bin, env_overrides=overrides)
    runner.start()
    yield runner
    runner.stop(cleanup=True)
