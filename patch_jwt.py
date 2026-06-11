import subprocess
subprocess.run(["pip", "uninstall", "-y", "jwt"])
subprocess.run(["pip", "uninstall", "-y", "PyJWT"])
subprocess.run(["pip", "install", "PyJWT", "cryptography"])
