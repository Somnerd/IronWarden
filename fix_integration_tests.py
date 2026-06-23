import os
import re

test_dir = "integration_tests/tests"
for root, _, files in os.walk(test_dir):
    for f in files:
        if f.endswith(".rs"):
            path = os.path.join(root, f)
            with open(path, "r") as file:
                content = file.read()
            
            # Revert axum::body::Bytes to bytes::Bytes
            content = content.replace("axum::body::Bytes", "bytes::Bytes")
            
            # Fix Some(&session).await) to Some(&session)).await
            content = content.replace("Some(&session).await)", "Some(&session)).await")
            content = content.replace("Some(&new_session).await)", "Some(&new_session)).await")
            
            # Fix report.sanitized_text.contains to String::from_utf8_lossy(&report.sanitized_text).contains
            content = content.replace("report.sanitized_text.contains", "String::from_utf8_lossy(&report.sanitized_text).contains")
            content = content.replace("report1.sanitized_text.contains", "String::from_utf8_lossy(&report1.sanitized_text).contains")
            content = content.replace("report2.sanitized_text.contains", "String::from_utf8_lossy(&report2.sanitized_text).contains")
            content = content.replace("report3.sanitized_text.contains", "String::from_utf8_lossy(&report3.sanitized_text).contains")
            content = content.replace("report4.sanitized_text.contains", "String::from_utf8_lossy(&report4.sanitized_text).contains")
            content = content.replace("report5.sanitized_text.contains", "String::from_utf8_lossy(&report5.sanitized_text).contains")
            
            # Fix format strings for report.sanitized_text
            content = content.replace("{}", "{:?}")
            
            with open(path, "w") as file:
                file.write(content)
