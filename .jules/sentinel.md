## 2025-06-16 - [Secure Deletion in SQLite]
**Vulnerability:** The application was using `DELETE FROM` to remove sensitive user data and raw PII logs without securely erasing the deleted content, potentially leaving data physically intact on disk.
**Learning:** In SQLite, `DELETE` only marks space as free. Using `VACUUM` after every deletion causes severe performance issues and database locks. The performant standard is setting `PRAGMA secure_delete = ON;`, which overwrites deleted content with zeros immediately.
**Prevention:** Enable `PRAGMA secure_delete = ON;` on database connections to ensure physical destruction of deleted data from the filesystem, complying with GDPR/Sovereign standards.
