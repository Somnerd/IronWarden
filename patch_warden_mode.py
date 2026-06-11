import re
with open("app/src/main.rs", "r") as f:
    content = f.read()

content = content.replace("deployment_profile", "warden_mode")

with open("app/src/main.rs", "w") as f:
    f.write(content)
