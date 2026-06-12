## 2024-06-10 - `any` over loop for has_before/has_after
**Learning:** Found an opportunity to replace `while let Some(c) = chars.next()` loops with `any` for `has_before` and `has_after` checking. `any` provides early returns naturally.
**Action:** Replace `while let` with iterators for performance gains.
## 2024-06-11 - `starts_with` and `ends_with` over `chars().next()` and `chars().last()`
**Learning:** Found an opportunity to replace `text.chars().last().map_or(...)` and `text.chars().next().map_or(...)` with `text.ends_with(...)` and `text.starts_with(...)` for performance gains. `ends_with` and `starts_with` are much faster because they operate on bytes/slices rather than creating a full character iterator.
**Action:** Replace `chars().last()` and `chars().next()` with `ends_with` and `starts_with` for boundary checks.
