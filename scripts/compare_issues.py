import os
import json
import urllib.request
import urllib.error
import re

TOKEN = "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"
REPO = "Somnerd/IronWarden"
ISSUES_DIR = ".github/issues"

def get_existing_issues():
    url = f"https://api.github.com/repos/{REPO}/issues?state=all&per_page=100"
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "IronWarden-Auditor"
    }

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception as e:
        print(f"❌ Failed to fetch issues from GitHub: {e}")
        return []

def main():
    existing = get_existing_issues()
    print(f"Loaded {len(existing)} issues from GitHub ({REPO}).\n")

    # Index existing issues by title for easy lookup
    existing_titles = {issue['title'].lower().strip(): issue for issue in existing}

    if not os.path.exists(ISSUES_DIR):
        print(f"❌ Local issues directory {ISSUES_DIR} not found.")
        return

    local_files = [f for f in os.listdir(ISSUES_DIR) if f.endswith(".md")]
    if not local_files:
        print(f"❌ No local issue templates found.")
        return

    print("Comparing local templates against GitHub issues:")
    print("-" * 60)

    missing_issues = []

    for filename in sorted(local_files):
        filepath = os.path.join(ISSUES_DIR, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        title_match = re.search(r"^# Title:\s*(.*)$", content, re.MULTILINE)
        if not title_match:
            continue

        title = title_match.group(1).strip()
        title_lower = title.lower().strip()

        if title_lower in existing_titles:
            gh_issue = existing_titles[title_lower]
            state = gh_issue['state'].upper()
            url = gh_issue['html_url']
            print(f"✅ [GitHub {state}] '{title}' -> {url}")
        else:
            print(f"❌ [MISSING]      '{title}' (Not on GitHub)")
            missing_issues.append((title, filepath))

    print("-" * 60)
    if missing_issues:
        print(f"\nFound {len(missing_issues)} missing issues that need to be created.")
    else:
        print("\nAll local issues are already created on GitHub!")

if __name__ == "__main__":
    main()
