import os
import re

test_dir = "integration_tests/tests"
for root, _, files in os.walk(test_dir):
    for f in files:
        if f.endswith(".rs"):
            path = os.path.join(root, f)
            with open(path, "r") as file:
                content = file.read()
            
            # Fix Some(&mut session).await)
            content = re.sub(r'Some\((&[^)]+)\)\.await\)', r'Some(\1)).await', content)
            
            # Make main async
            if "async fn main" not in content and "fn main(" in content:
                content = content.replace("fn main()", "#[tokio::main]\nasync fn main()")
            
            # Change #[test] fn to #[tokio::test] async fn
            content = re.sub(r'#\[test\]\s+fn\s+', r'#[tokio::test]\nasync fn ', content)
            
            # Change #[tokio::test] fn to #[tokio::test] async fn
            content = re.sub(r'#\[tokio::test\]\s+(?!async\s)fn\s+', r'#[tokio::test]\nasync fn ', content)
            
            # Fix queue.enqueue
            content = content.replace("queue.enqueue(\n        report.sanitized_text,", "queue.enqueue(\n        String::from_utf8_lossy(&report.sanitized_text).into_owned(),")
            content = content.replace("queue.enqueue(\n        report.sanitized_text.clone(),", "queue.enqueue(\n        String::from_utf8_lossy(&report.sanitized_text).into_owned(),")
            # In case it's on one line:
            content = content.replace("queue.enqueue(report.sanitized_text,", "queue.enqueue(String::from_utf8_lossy(&report.sanitized_text).into_owned(),")
            content = content.replace("queue.enqueue(report.sanitized_text.clone(),", "queue.enqueue(String::from_utf8_lossy(&report.sanitized_text).into_owned(),")
            
            # Fix contexts[0]
            content = content.replace("bytes::Bytes::from(contexts[0])", "bytes::Bytes::from(contexts[0].clone())")
            
            # Fix ingress_semaphore
            content = content.replace("jwt_public_key,\n        })", "jwt_public_key,\n            ingress_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(100)),\n        })")
            
            with open(path, "w") as file:
                file.write(content)
