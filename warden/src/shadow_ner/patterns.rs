use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

pub static GLOBAL_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Z\u{0386}\u{0388}-\u{038A}\u{038C}\u{038E}-\u{03A1}\u{03A3}-\u{03A9}][\u{03B1}-\u{03C9}\u{03AC}-\u{03CE}a-z]+(?:[\s\-\x27]+(?:(?:(?i:da|de|del|della|der|den|di|du|ter|ten|van|von|ibn|bin|al|el|la|le|des)|[A-Z\u{0386}\u{0388}-\u{038A}\u{038C}\u{038E}-\u{03A1}\u{03A3}-\u{03A9}]\.)[\s\-\x27]+)*[A-Z\u{0386}\u{0388}-\u{038A}\u{038C}\u{038E}-\u{03A1}\u{03A3}-\u{03A9}][\u{03B1}-\u{03C9}\u{03AC}-\u{03CE}a-z]+)+\b").unwrap()
});

pub static INITIAL_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:[A-Za-z\u{0386}-\u{03CE}]\.[\s\-']*){1,3}([A-Za-z\u{0386}-\u{03CE}][\u{03B1}-\u{03C9}\u{03AC}-\u{03CE}a-z]{2,})\b").unwrap()
});

pub static HONORIFIC_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Rev|Hon)\.?[\s\-']+([A-Z\u{0386}\u{0388}-\u{038A}\u{038C}\u{038E}-\u{03A1}\u{03A3}-\u{03A9}][\u{03B1}-\u{03C9}\u{03AC}-\u{03CE}a-z]{2,})\b").unwrap()
});

pub static CONTEXT_ROLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:Patient|Per|Attn|Client|Customer)[\s\-']+([A-Z\u{0386}\u{0388}-\u{038A}\u{038C}\u{038E}-\u{03A1}\u{03A3}-\u{03A9}][\u{03B1}-\u{03C9}\u{03AC}-\u{03CE}a-z]{2,})\b").unwrap()
});

pub static CAPITALIZED_WORD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Z\u{0386}\u{0388}-\u{038A}\u{038C}\u{038E}-\u{03A1}\u{03A3}-\u{03A9}][\u{03B1}-\u{03C9}\u{03AC}-\u{03CE}a-z]{2,}\b").unwrap()
});

pub static GREEK_NAME_PAIR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[a-z\u{0386}-\u{03CE}]{3,}\s+[a-z\u{0386}-\u{03CE}]{3,}(?:poulos|poulou|poulo|idis|idi|iadis|iadi|akis|aki|oglou|akos|akou|ako|atos|atou|ato|eas|ea|ianni|yianni|omou|ou|πουλος|πουλου|πουλο|ίδης|ίδη|ιάδης|ιάδη|άκης|άκη|όγλου|ογλου|όπουλος|όπουλου|όπουλο|άκος|άκου|άκο|άτος|άτου|άτο|έας|έα|ιδης|ιδη|ιαδης|ιαδη|ακης|ακη|οπουλος|οπουλου|οπουλο|ακος|ακου|ακο|ατος|ατου|ατο|εας|εα|ης|ου|ος|ας|α|ων|η)\b").unwrap()
});

pub static GREEK_PATRONYMIC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[a-z]{3,}(?:poulos|poulou|poulo|idis|idi|iadis|iadi|akis|aki|oglou|akos|akou|ako|atos|atou|ato|eas|ea|ianni|yianni)|[\u{0386}-\u{03CE}]{3,}(?:πουλος|πουλου|πουλο|ίδης|ίδη|ιάδης|ιάδη|άκης|άκη|όγλου|ογλου|όπουλος|όπουλου|όπουλο|άκος|άκου|άκο|άτος|άτου|άτο|έας|έα|ιδης|ιδη|ιαδης|ιαδη|ακης|ακη|οπουλος|οπουλου|οπουλο|ακος|ακου|ακο|ατος|ατου|ατο|εας|εα))\b").unwrap()
});

pub static GREEK_MORPHOLOGICAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[\u{0386}-\u{03CE}]{3,}(?:ης|ου|ος|ας|ων|η)\b").unwrap());

pub static ARABIC_MORPHOLOGICAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:al-|el-|ibn\s+|bin\s+)[a-z\u{0621}-\u{064A}]{3,}\b").unwrap()
});

pub static CONVERSATIONAL_INTRO_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:my\s+name\s+is|i\s+am|i'm|contact|email|ping|dm|ask|cc|attn[:\.]?|per|patient|client|mr\.?|mrs\.?|ms\.?|dr\.?|directly\s+to|send\s+(?:the\s+[\w\s]+\s+)?(?:directly\s+)?to)\s+|@)(['"]?[a-z\u{0386}-\u{03CE}]{2,}(?:[\s\-']+[a-z\u{0386}-\u{03CE}]{2,}){0,2}['"]?)\b"#).unwrap()
});

pub static LOWERCASE_STOPWORDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../../config/dicts/stopwords.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
});

pub static PROTECTED_SURNAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../../config/dicts/protected_surnames.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
});

pub static IMPERATIVE_VERBS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../../config/dicts/imperative_verbs.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
});

pub static GEOGRAPHIC_PROPER_NOUNS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../../config/dicts/geographic_proper_nouns.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
});

pub static ROLE_NOUN_BLOCKLIST: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../../config/dicts/role_nouns.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
});

pub static COMMON_SENTENCE_STARTERS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../../config/dicts/sentence_starters.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
});

pub static GREETINGS_BLOCKLIST: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../../config/dicts/greetings.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
});

pub static TECH_AND_COMMON_STOPWORDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../../config/dicts/tech_stopwords.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
});
