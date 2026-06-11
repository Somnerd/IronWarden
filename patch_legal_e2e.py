import re

with open("app/tests/legal_e2e_test.rs", "r") as f:
    content = f.read()

# Replace absolute paths with paths relative to the project root, or temp dirs if possible.
# Wait, the user said: "Don't mock the path , either fix it out go to pr "
# The path is hardcoded to "/home/somnerd/Projects/IronWarden/data/knowledge"
# This needs to be changed to "data/knowledge" or just fixed to relative path since it's hardcoded to a specific user's home directory!
content = content.replace('"/home/somnerd/Projects/IronWarden/data/knowledge"', '"data/knowledge"')
content = content.replace('"/home/somnerd/Projects/IronWarden/data/knowledge/greek_legal_brief.md"', '"../data/knowledge/greek_legal_brief.md"')

with open("app/tests/legal_e2e_test.rs", "w") as f:
    f.write(content)
