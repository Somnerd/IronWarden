import re
import os

files = [
    'core/src/crypto.rs',
    'core/src/traits.rs',
    'mcp/src/server.rs',
    'warden/src/config.rs',
    'warden/src/configurator.rs',
    'warden/src/normalize.rs',
    'worker/src/audit.rs',
    'worker/src/bridge.rs',
    'worker/src/librarian.rs',
    'worker/src/ocr.rs',
    'worker/src/searchboost.rs',
    'worker/src/storage.rs'
]

for filepath in files:
    if not os.path.exists(filepath):
        continue
        
    with open(filepath, 'r') as f:
        content = f.read()

    # Find the start of the tests module
    test_start = content.find('#[cfg(test)]\nmod tests {')
    if test_start == -1:
        test_start = content.find('#[cfg(test)]\r\nmod tests {')

    if test_start != -1:
        functional_code = content[:test_start]
        test_code = content[test_start:]
        
        # Extract the inner body of mod tests { ... }
        # To handle nested braces, we can just do a simple curly brace parser, or assume it reaches the end of the file.
        # Since these are typically at the bottom of the file, we can just find the first '{' and strip the last '}'.
        
        start_brace = test_code.find('{')
        end_brace = test_code.rfind('}')
        
        if start_brace != -1 and end_brace != -1:
            inner_tests = test_code[start_brace+1:end_brace].strip()
            
            # Determine new test file name
            dir_name = os.path.dirname(filepath)
            base_name = os.path.basename(filepath)
            name_no_ext = os.path.splitext(base_name)[0]
            test_filename = f"{name_no_ext}_tests.rs"
            test_filepath = os.path.join(dir_name, test_filename)
            
            with open(test_filepath, 'w') as f:
                f.write(inner_tests + '\n')
                
            functional_code += f'#[cfg(test)]\n#[path = "{test_filename}"]\nmod tests;\n'
            
            with open(filepath, 'w') as f:
                f.write(functional_code)
            
            print(f"Processed {filepath} -> {test_filepath}")
        else:
            print(f"Could not parse braces in {filepath}")

