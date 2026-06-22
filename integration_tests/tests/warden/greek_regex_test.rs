// This file executes a basic regex search test using a specialized pattern designed to match both English and Greek name structures (including uppercase and accented characters).
use regex::Regex;

fn main() {
    let re = Regex::new(r"\b[A-Z\u0386\u0388-\u038A\u038C\u038E\u038F\u0391-\u03A9][\u03B1-\u03C9\u03AC-\u03CEa-z]+(?:\s+(?:[a-z]{1,3}\s+)*[A-Z\u0386\u0388-\u038A\u038C\u038E\u038F\u0391-\u03A9][\u03B1-\u03C9\u03AC-\u03CEa-z]+)+\b").unwrap();
    let text = "Geia sou Nikolaos Papadopoulos";
    if let Some(mat) = re.find(text) {
        println!("Match: '{}'", mat.as_str());
    } else {
        println!("No match");
    }
}
