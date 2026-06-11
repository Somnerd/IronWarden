import re
import os

if not os.path.exists("data/knowledge"):
    os.makedirs("data/knowledge", exist_ok=True)

with open("data/knowledge/greek_legal_brief.md", "w") as f:
    f.write("# Greek Legal Brief\nNikolas Alexandrakis AFM: 123456789")
