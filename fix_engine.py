import re

with open('warden/src/engine.rs', 'r') as f:
    content = f.read()

# Find the start of the tests module
test_start = content.find('#[cfg(test)]\nmod tests {')
if test_start == -1:
    test_start = content.find('#[cfg(test)]\r\nmod tests {')

if test_start != -1:
    functional_code = content[:test_start]
    test_code = content[test_start:]
    
    # We want to keep the #[cfg(test)] module but in a separate file
    # tests code looks like:
    # #[cfg(test)]
    # mod tests {
    #     use super::*; ... }
    # So we can just extract the inner parts to engine_tests.rs
    
    inner_tests_match = re.search(r'mod tests \{(.*)\}\s*$', test_code, re.DOTALL)
    if inner_tests_match:
        inner_tests = inner_tests_match.group(1).strip()
    else:
        inner_tests = test_code # fallback
        
    # Resolve conflicts in inner_tests
    # The conflict is:
    # <<<<<<< HEAD
    #         let config = crate::configurator::GlobalConfig::resolve().unwrap();
    #         let (warden_config, _) = crate::config::WardenConfig::from_manifest(&config.warden_manifest_path).unwrap();
    #         let pepper = secrecy::SecretVec::new(config.warden_pepper.unwrap_or_else(|| vec![0u8; 32]));
    #         let engine = warden_config.build_engine(&pepper).await.unwrap();
    # =======
    #         let yaml = r#"
    #             name: "Test"
    #             rules: []
    #             heuristics: []
    #         "#;
    #         let config: crate::config::WardenConfig = serde_yaml::from_str(yaml).unwrap();
    #         let pepper = secrecy::SecretVec::new(vec![0u8; 32]);
    #         let engine = config.compile_engine(&pepper).unwrap();
    # >>>>>>> origin/dev
    
    def resolve_conflict(match):
        head = match.group(1)
        origin = match.group(2)
        # We will keep the origin/dev version because it uses the correct compile_engine
        return origin
        
    inner_tests_resolved = re.sub(
        r'<<<<<<< HEAD\n(.*?)\n=======\n(.*?)\n>>>>>>> origin/dev',
        resolve_conflict,
        inner_tests,
        flags=re.DOTALL
    )
    
    with open('warden/src/engine_tests.rs', 'w') as f:
        f.write(inner_tests_resolved + '\n')
        
    functional_code += '#[cfg(test)]\n#[path = "engine_tests.rs"]\nmod tests;\n'
    
    with open('warden/src/engine.rs', 'w') as f:
        f.write(functional_code)
