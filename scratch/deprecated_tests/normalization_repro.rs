use iw_warden::normalize::Normalizer;
fn main() {
    let input = "Hello Al\u{0456}ce Smith.";
    let res = Normalizer::normalize(input);
    println!("Input: {}", input);
    println!("ASCII: {}", res.normalized_ascii);
    println!("Unicode: {}", res.normalized_unicode);
    for (i, c) in res.normalized_ascii.char_indices() {
        println!("ASCII idx {}: char '{}', orig offset {}", i, c, res.ascii_to_original.get_original_offset(i));
    }
}
