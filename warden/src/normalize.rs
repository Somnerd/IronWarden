use any_ascii::any_ascii_char;
use unicode_normalization::UnicodeNormalization;

pub struct OffsetMap {
    pub normalized_to_original: Vec<usize>,
}

impl OffsetMap {
    /// Maps a normalized byte index back to its original byte index.
    pub fn get_original_offset(&self, normalized_idx: usize) -> usize {
        if normalized_idx >= self.normalized_to_original.len() {
            // Return the end of the original string for boundary cases
            self.normalized_to_original.last().cloned().unwrap_or(0)
        } else {
            self.normalized_to_original[normalized_idx]
        }
    }
}

pub struct NormalizationResult {
    pub normalized_ascii: String,
    pub ascii_to_original: OffsetMap,
    pub normalized_unicode: String,
    pub unicode_to_original: OffsetMap,
    pub stripped: String,
    pub stripped_to_original: OffsetMap,
    pub original_to_unicode: Vec<usize>,
    pub original_to_ascii: Vec<usize>,
}

impl NormalizationResult {
    fn clear(&mut self, input_len: usize) {
        self.normalized_ascii.clear();
        self.ascii_to_original.normalized_to_original.clear();
        self.normalized_unicode.clear();
        self.unicode_to_original.normalized_to_original.clear();
        self.stripped.clear();
        self.stripped_to_original.normalized_to_original.clear();
        self.original_to_unicode.clear();
        self.original_to_ascii.clear();
        self.original_to_unicode.resize(input_len + 1, 0);
        self.original_to_ascii.resize(input_len + 1, 0);
    }
}

thread_local! {
    static NORM_BUFFER: std::cell::RefCell<NormalizationResult> = std::cell::RefCell::new(NormalizationResult {
        normalized_ascii: String::with_capacity(32_768),
        ascii_to_original: OffsetMap { normalized_to_original: Vec::with_capacity(32_768) },
        normalized_unicode: String::with_capacity(32_768),
        unicode_to_original: OffsetMap { normalized_to_original: Vec::with_capacity(32_768) },
        stripped: String::with_capacity(32_768),
        stripped_to_original: OffsetMap { normalized_to_original: Vec::with_capacity(32_768) },
        original_to_unicode: Vec::with_capacity(32_768),
        original_to_ascii: Vec::with_capacity(32_768),
    });
}

pub struct Normalizer;

impl Normalizer {
    /// Optimized zero-allocation normalization using thread-local pools.
    /// The buffer is cleared, populated, and then immutably borrowed for the closure.
    pub fn with_normalized<F, R>(input: &str, f: F) -> R
    where
        F: FnOnce(&NormalizationResult) -> R,
    {
        NORM_BUFFER.with(|buf| {
            {
                let mut b = buf.borrow_mut();
                b.clear(input.len());

                for (orig_idx, c) in input.char_indices() {
                    // 1. Process for ASCII (Homoglyph detection)
                    let ascii_start = b.normalized_ascii.len();
                    let ascii_equiv = any_ascii_char(c);
                    for norm_c in ascii_equiv.nfkc() {
                        if !Self::is_invisible(norm_c) {
                            let start_pos = b.normalized_ascii.len();
                            b.normalized_ascii.push(norm_c);
                            let end_pos = b.normalized_ascii.len();
                            for _ in start_pos..end_pos {
                                b.ascii_to_original.normalized_to_original.push(orig_idx);
                            }

                            // --- SECURITY FIX (Section 2.2 / Finding B.2): Flexible Separator Evasion ---
                            if norm_c.is_alphanumeric() {
                                let s_start = b.stripped.len();
                                b.stripped.push(norm_c.to_ascii_lowercase());
                                let s_end = b.stripped.len();
                                for _ in s_start..s_end {
                                    b.stripped_to_original.normalized_to_original.push(orig_idx);
                                }
                            }
                        }
                    }
                    for i in 0..c.len_utf8() {
                        if orig_idx + i < b.original_to_ascii.len() {
                            b.original_to_ascii[orig_idx + i] = ascii_start;
                        }
                    }

                    // 2. Process for Unicode (Preserving Greek, etc.)
                    let unicode_start = b.normalized_unicode.len();
                    if !Self::is_invisible(c) {
                        for norm_c in c.nfkc() {
                            let start_pos = b.normalized_unicode.len();
                            b.normalized_unicode.push(norm_c);
                            let end_pos = b.normalized_unicode.len();
                            for _ in start_pos..end_pos {
                                b.unicode_to_original.normalized_to_original.push(orig_idx);
                            }
                        }
                    }
                    // Fill original_to_unicode for all byte positions of this character
                    for i in 0..c.len_utf8() {
                        if orig_idx + i < b.original_to_unicode.len() {
                            b.original_to_unicode[orig_idx + i] = unicode_start;
                        }
                    }
                }
                b.ascii_to_original.normalized_to_original.push(input.len());
                b.unicode_to_original
                    .normalized_to_original
                    .push(input.len());
                b.stripped_to_original
                    .normalized_to_original
                    .push(input.len());

                let norm_unicode_len = b.normalized_unicode.len();
                b.original_to_unicode[input.len()] = norm_unicode_len;
                let norm_ascii_len = b.normalized_ascii.len();
                b.original_to_ascii[input.len()] = norm_ascii_len;
            } // Mutable borrow is dropped here!

            // Execute the inner block with an immutable borrow.
            let b = buf.borrow();
            f(&b)
        })
    }

    fn is_invisible(c: char) -> bool {
        // Broaden detection to all Unicode Format (Cf) and Control (Cc) characters,
        // as well as other non-spacing characters used for evasion.
        c.is_control() ||
        ('\u{200B}'..='\u{200F}').contains(&c) || // ZWSP, ZWNJ, ZWJ, LRM, RLM
        ('\u{202A}'..='\u{202E}').contains(&c) || // LRE, RLE, PDF, LRO, RLO
        ('\u{2060}'..='\u{206F}').contains(&c) || // Word Joiner, Format characters
        ('\u{FEFF}' == c) // BOM
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn fuzz_normalization_offset_consistency(s in "\\PC*") {
            Normalizer::with_normalized(&s, |res| {
                // 1. Boundary check: Every normalized byte must map back to a valid original byte index
                for i in 0..res.normalized_ascii.len() {
                    let orig_idx = res.ascii_to_original.get_original_offset(i);
                    prop_assert!(orig_idx < s.len() || (s.is_empty() && orig_idx == 0));
                }

                // 2. Transformation check: The output must be pure ASCII (enforced by any_ascii)
                prop_assert!(res.normalized_ascii.is_ascii());

                // 3. Invisible character check: Output should not contain ZWSP etc.
                for c in res.normalized_ascii.chars() {
                    prop_assert!(!Normalizer::is_invisible(c));
                }
                Ok(())
            })?;
        }
    }

    #[test]
    fn test_specific_edge_cases() {
        let input = "A\u{200B}B"; // Invisible ZWSP (3 bytes: E2 80 8B)
        Normalizer::with_normalized(input, |res| {
            assert_eq!(res.normalized_ascii, "AB");
            assert_eq!(res.ascii_to_original.get_original_offset(0), 0); // A
            assert_eq!(res.ascii_to_original.get_original_offset(1), 4); // B (skips 3-byte ZWSP at indices 1,2,3)
        });
    }
}
