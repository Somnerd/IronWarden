use unicode_normalization::UnicodeNormalization;
use regex::Regex;
use once_cell::sync::Lazy;
use any_ascii::any_ascii_char;

static INVISIBLE_CHARS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[\u200B-\u200D\uFEFF]").expect("Failed to compile invisible char regex")
});

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
    pub original_to_unicode: Vec<usize>,
}

pub struct Normalizer;

impl Normalizer {
    /// Optimized normalization that produces both ASCII-normalized and Unicode-normalized versions.
    pub fn normalize(input: &str) -> NormalizationResult {
        let mut normalized_ascii = String::with_capacity(input.len());
        let mut ascii_mapping = Vec::with_capacity(input.len() + 1);
        
        let mut normalized_unicode = String::with_capacity(input.len());
        let mut unicode_mapping = Vec::with_capacity(input.len() + 1);
        let mut original_to_unicode = vec![0; input.len() + 1];

        for (orig_idx, c) in input.char_indices() {
            // 1. Process for ASCII (Homoglyph detection)
            let ascii_equiv = any_ascii_char(c);
            for norm_c in ascii_equiv.nfkc() {
                if !Self::is_invisible(norm_c) {
                    let start_pos = normalized_ascii.len();
                    normalized_ascii.push(norm_c);
                    let end_pos = normalized_ascii.len();
                    for _ in start_pos..end_pos {
                        ascii_mapping.push(orig_idx);
                    }
                }
            }

            // 2. Process for Unicode (Preserving Greek, etc.)
            let unicode_start = normalized_unicode.len();
            if !Self::is_invisible(c) {
                for norm_c in c.nfkc() {
                    let start_pos = normalized_unicode.len();
                    normalized_unicode.push(norm_c);
                    let end_pos = normalized_unicode.len();
                    for _ in start_pos..end_pos {
                        unicode_mapping.push(orig_idx);
                    }
                }
            }
            // Fill original_to_unicode for all byte positions of this character
            for i in 0..c.len_utf8() {
                if orig_idx + i < original_to_unicode.len() {
                    original_to_unicode[orig_idx + i] = unicode_start;
                }
            }
        }
        ascii_mapping.push(input.len());
        unicode_mapping.push(input.len());
        original_to_unicode[input.len()] = normalized_unicode.len();

        NormalizationResult {
            normalized_ascii,
            ascii_to_original: OffsetMap { normalized_to_original: ascii_mapping },
            normalized_unicode,
            unicode_to_original: OffsetMap { normalized_to_original: unicode_mapping },
            original_to_unicode,
        }
    }

    fn is_invisible(c: char) -> bool {
        match c {
            '\u{200B}'..='\u{200D}' | '\u{FEFF}' => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn fuzz_normalization_offset_consistency(s in "\\PC*") {
            let res = Normalizer::normalize(&s);
            
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
        }
    }

    #[test]
    fn test_specific_edge_cases() {
        let input = "A\u{200B}B"; // Invisible ZWSP (3 bytes: E2 80 8B)
        let res = Normalizer::normalize(input);
        assert_eq!(res.normalized_ascii, "AB");
        assert_eq!(res.ascii_to_original.get_original_offset(0), 0); // A
        assert_eq!(res.ascii_to_original.get_original_offset(1), 4); // B (skips 3-byte ZWSP at indices 1,2,3)
    }
}
