## 2024-06-10 - `any` over loop for has_before/has_after
**Learning:** Found an opportunity to replace `while let Some(c) = chars.next()` loops with `any` for `has_before` and `has_after` checking. `any` provides early returns naturally.
**Action:** Replace `while let` with iterators for performance gains.
