import pytest
import subprocess
import json
import time
import os
import signal
import threading

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

        self.env = {
            **os.environ,
            "WARDEN_MODE": "ephemeral",
            "WARDEN_PEPPER": "a_very_secret_pepper_32_bytes_long",
            "OPENAI_API_KEY": "sk-mock-key",
            "JWT_SECRET": "another_very_secret_key_32_bytes_long",
            "DATABASE_URL": "postgres://somnerd:postgres@localhost:5432/ironwarden",
            "REDIS_URL": "redis://localhost:6379",
            "AUDIT_DB_PATH": os.path.join(project_root, f"test_audit_{unique_id}.db"),
            "LANCEDB_PATH": os.path.join(project_root, f"test_lancedb_{unique_id}"),
            "WARDEN_CONFIG_PATH": os.path.join(project_root, "config/regions"),
            "BRIDGE_PORT": "14141",
            "LOG_FORMAT": "text",
            "LD_LIBRARY_PATH": ld_library_path,
            "LD_PRELOAD": ld_preload,
            **(env_overrides or {})
        }
        self.process = None
        self.stderr_output = []

    def start(self):
        # Cleanup old files
        if os.path.exists(self.env["AUDIT_DB_PATH"]):
            os.remove(self.env["AUDIT_DB_PATH"])

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
            if any("IronWarden Forge ignited" in line for line in self.stderr_output):
                ignited = True
                break
            if self.process.poll() is not None:
                stderr = "\n".join(self.stderr_output)
                raise RuntimeError(f"IronWarden failed to start. Exit code: {self.process.returncode}\nStderr: {stderr}")
            time.sleep(0.1)

        if not ignited:
             stderr = "\n".join(self.stderr_output)
             self.stop()
             raise RuntimeError(f"IronWarden timed out starting. Stderr:\n{stderr}")
        
        # Settle delay to ensure background DB tasks are fully committed
        time.sleep(1)

    def _read_stderr(self):
        while not self.stop_event.is_set():
            line = self.process.stderr.readline()
            if not line:
                break
            line = line.strip()
            self.stderr_output.append(line)
            print(f"DEBUG LOG: {line}")

    def stop(self):
        if self.process:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.stop_event.set()

        # Cleanup temporary resources
        try:
            if "AUDIT_DB_PATH" in self.env and os.path.exists(self.env["AUDIT_DB_PATH"]):
                os.remove(self.env["AUDIT_DB_PATH"])
                # Also remove WAL/SHM files
                for ext in ["-shm", "-wal"]:
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
def warden(warden_bin):
    runner = IronWardenRunner(warden_bin)
    runner.start()
    yield runner
    runner.stop()

@pytest.fixture
def jwt_factory(warden):
    import jwt
    def _create_token(username, roles=None):
        if roles is None:
            roles = ["admin"]
        secret = warden.env["JWT_SECRET"]
        payload = {
            "sub": username,
            "exp": int(time.time()) + 3600,
            "roles": roles
        }
        return jwt.encode(payload, secret, algorithm="HS256")
    return _create_token
