import re

with open('warden/src/engine.rs', 'r') as f:
    content = f.read()

# 1. Update UnifiedMatch struct
content = content.replace('struct UnifiedMatch {', "struct UnifiedMatch<'a> {")
content = content.replace('    text: String,', "    text: std::borrow::Cow<'a, str>,")

# 2. Update Vecs
content = content.replace('Vec<UnifiedMatch>', "Vec<UnifiedMatch<'a>>")

# 3. Update text: ...to_string()
# For normalized[unicode_start..unicode_end].to_string()
content = content.replace(
    'text: normalized[unicode_start..unicode_end].to_string(),',
    'text: std::borrow::Cow::Borrowed(&normalized[unicode_start..unicode_end]),'
)
# For mat.as_str().to_string()
content = content.replace(
    'text: mat.as_str().to_string(),',
    'text: std::borrow::Cow::Borrowed(mat.as_str()),'
)

# 4. Update text: miss.text
# Here miss.text is a String, so we need Cow::Owned
content = content.replace(
    'text: miss.text,',
    'text: std::borrow::Cow::Owned(miss.text.clone()),'
)

# 5. Update sanitized_text construction
# Old: 
# let mut sanitized_text = String::new();
# ...
# sanitized_text.push_str(&normalized[last_pos..mat.start]);

# We will just replace `let mut sanitized_text = String::new();` with `let mut sanitized_text = String::with_capacity(normalized.len() + 128);`
content = content.replace(
    'let mut sanitized_text = String::new();',
    'let mut sanitized_text = String::with_capacity(normalized.len() + 128);'
)

with open('warden/src/engine.rs', 'w') as f:
    f.write(content)

