import os
import json
import urllib.request
import urllib.error
import re

def get_existing_issue_titles(token, repo):
    url = f"https://api.github.com/repos/{repo}/issues?state=all&per_page=100"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "IronWarden-Setup-Script"
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            issues = json.loads(response.read().decode('utf-8'))
            return {issue['title'].lower().strip() for issue in issues}
    except Exception as e:
        print(f"⚠️ Warning: Could not fetch existing issues to check for duplicates: {e}")
        return set()

def create_issue(token, repo, title, body):
    url = f"https://api.github.com/repos/{repo}/issues"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
        "User-Agent": "IronWarden-Setup-Script"
    }
    
    payload = {
        "title": title,
        "body": body,
        "labels": ["pre-launch"]
    }
    
    req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers, method='POST')
    
    try:
        with urllib.request.urlopen(req) as response:
            res_data = json.loads(response.read().decode('utf-8'))
            print(f"✅ Successfully created issue: {res_data.get('html_url')}")
            return res_data.get('html_url')
    except urllib.error.HTTPError as e:
        error_msg = e.read().decode('utf-8')
        print(f"❌ Failed to create issue. HTTP {e.code}: {e.reason}")
        print(f"Details: {error_msg}")
        return None
    except Exception as e:
        print(f"❌ Error occurred: {e}")
        return None

def main():
    token = os.environ.get("GITHUB_TOKEN") or "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"
    if not token:
        print("❌ Error: GITHUB_TOKEN environment variable is not set.")
        return
        
    repo = "Somnerd/IronWarden"
    issues_dir = ".github/issues"
    
    if not os.path.exists(issues_dir):
        print(f"❌ Error: {issues_dir} directory not found.")
        return
        
    issue_files = [f for f in os.listdir(issues_dir) if f.endswith(".md")]
    if not issue_files:
        print(f"❌ Error: No markdown files found in {issues_dir}")
        return
        
    # Fetch existing issues to prevent duplicates
    existing_titles = get_existing_issue_titles(token, repo)
    
    print(f"🚀 Found {len(issue_files)} local issue templates. Checking duplicates and creating...\n")
    
    for filename in sorted(issue_files):
        filepath = os.path.join(issues_dir, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Parse title and body
        title_match = re.search(r"^# Title:\s*(.*)$", content, re.MULTILINE)
        if not title_match:
            print(f"⚠️ Warning: Could not find title in {filename}. Skipping.")
            continue
            
        title = title_match.group(1).strip()
        
        # Check duplicate
        if title.lower().strip() in existing_titles:
            print(f"⏭️ Skipping: '{title}' (Already exists on GitHub)")
            continue
            
        # The body is everything after the title line
        body = re.sub(r"^#\s*Title:.*$\n", "", content, flags=re.MULTILINE).strip()
        
        print(f"Creating: '{title}'...")
        create_issue(token, repo, title, body)

if __name__ == "__main__":
    main()
