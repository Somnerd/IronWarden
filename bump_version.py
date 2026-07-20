import os
import glob

# Files to update
files_to_update = glob.glob('*/Cargo.toml') + ['README.md', 'mcp/src/server.rs']

for filepath in files_to_update:
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            content = f.read()
        
        if '0.1.30-alpha' in content:
            new_content = content.replace('0.1.30-alpha', '0.1.31-alpha')
            with open(filepath, 'w') as f:
                f.write(new_content)
            print(f"Updated {filepath}")
