## 📝 Description
<!-- Briefly describe the purpose of this change, bug fix, or feature. -->

## 🔗 Related Issues & Work Packages
<!-- Link any related GitHub issues or OpenProject work packages (e.g. Fixes #123, WP-102) -->

## 🛠️ Type of Change
- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 🔒 Security fix (hardens security invariants or fixes vulnerabilities)
- [ ] ⚡ Performance improvement
- [ ] 📚 Documentation update
- [ ] 🧹 Refactoring / Code cleanup

## 🛡️ Security Invariants Verification
IronWarden operates under a **Zero-Failure / Fail-Closed** mandate. Please check all verified invariants:
- [ ] **V-12 (Overlap Integrity):** Redact matches never mask Block rules.
- [ ] **V-14 (Leak-Proof Routing):** Only sanitized prompts are enqueued for upstream LLMs.
- [ ] **V-15 (Dual-Track NER):** Preserved homoglyph and script-aware normalization parity.
- [ ] **V-19 (AAD Session Isolation):** Session/job context bound to username with authenticated encryption.
- [ ] **Fail-Closed Persistence:** Tested database lock/full error handling.

## ✅ Pre-Merge Checklist
- [ ] Code follows project formatting standards (`cargo fmt --all -- --check`)
- [ ] Clippy checks pass with zero warnings (`cargo clippy --workspace --all-targets -- -D warnings`)
- [ ] All unit and integration tests pass (`cargo test --workspace`)
- [ ] No hardcoded secrets, keys, or credentials committed
- [ ] Documentation updated (`README.md`, `SECURITY.md`, `MODELS.md`, etc. if applicable)
