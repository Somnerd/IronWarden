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
