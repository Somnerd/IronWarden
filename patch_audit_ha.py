import re
with open("worker/src/audit.rs", "r") as f:
    content = f.read()

orig = """                    // We check the parent directory of the DB path, or the current dir as fallback
                    let db_parent = std::path::Path::new(&path_monitor).parent().unwrap_or(std::path::Path::new("."));
                    let path_cstr = std::ffi::CString::new(db_parent.to_string_lossy().into_owned()).unwrap_or_default();
                    if libc::statvfs(path_cstr.as_ptr(), &mut stat) == 0 {"""

replacement = """                    // We check the parent directory of the DB path, or the current dir as fallback
                    let db_parent = std::path::Path::new(&path_monitor).parent().unwrap_or(std::path::Path::new("."));
                    let path_str = db_parent.to_string_lossy().into_owned();
                    let path_to_use = if path_str.is_empty() { "." } else { &path_str };
                    let path_cstr = std::ffi::CString::new(path_to_use).unwrap_or_default();
                    if libc::statvfs(path_cstr.as_ptr(), &mut stat) == 0 {"""

content = content.replace(orig, replacement)

with open("worker/src/audit.rs", "w") as f:
    f.write(content)
