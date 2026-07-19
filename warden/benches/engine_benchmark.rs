use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::HashMap;
use regex::Regex;
use aho_corasick::{AhoCorasick, MatchKind};

fn regex_restore(response: &str, map: &HashMap<String, String>) -> String {
    if map.is_empty() { return response.to_string(); }

    let mut sorted_keys: Vec<&String> = map.keys().collect();
    sorted_keys.sort_by(|a, b| b.len().cmp(&a.len()));

    let tokens: Vec<String> = sorted_keys.into_iter().map(|k| regex::escape(k)).collect();
    let pattern = format!("({})", tokens.join("|"));
    let re = Regex::new(&pattern).unwrap();

    let result = re.replace_all(response, |caps: &regex::Captures| {
        let token = &caps[0];
        map.get(token).cloned().unwrap_or_else(|| token.to_string())
    });

    result.into_owned()
}

fn aho_restore(response: &str, map: &HashMap<String, String>) -> String {
    if map.is_empty() { return response.to_string(); }

    let keys: Vec<&String> = map.keys().collect();
    let values: Vec<&String> = map.values().collect();

    let ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .build(&keys)
        .unwrap();

    let mut result = String::new();
    ac.replace_all_with(response, &mut result, |mat, _, dst| {
        dst.push_str(values[mat.pattern()]);
        true
    });

    result
}

fn bench_restoration(c: &mut Criterion) {
    let mut map = HashMap::new();
    for i in 0..100 {
        map.insert(format!("{{{{TOKEN_{}}}}}", i), format!("Replacement_{}", i));
    }

    let response = "This is a response with {{TOKEN_10}} and {{TOKEN_50}} and maybe a {{TOKEN_99}} here and there.";

    let mut group = c.benchmark_group("restore_prompt");
    group.bench_function("regex_approach", |b| {
        b.iter(|| regex_restore(black_box(response), black_box(&map)))
    });
    group.bench_function("aho_corasick_approach", |b| {
        b.iter(|| aho_restore(black_box(response), black_box(&map)))
    });
    group.finish();
}

criterion_group!(benches, bench_restoration);


fn replace_restore(response: &str, map: &HashMap<String, String>) -> String {
    let mut restored = response.to_string();
    let mut sorted_keys: Vec<&String> = map.keys().collect();
    sorted_keys.sort_by(|a, b| b.len().cmp(&a.len()));

    for token in sorted_keys {
        if let Some(original) = map.get(token) {
            restored = restored.replace(token, original);
        }
    }

    restored
}

fn bench_restoration2(c: &mut Criterion) {
    let mut map = HashMap::new();
    for i in 0..100 {
        map.insert(format!("{{{{TOKEN_{}}}}}", i), format!("Replacement_{}", i));
    }

    let response = "This is a response with {{TOKEN_10}} and {{TOKEN_50}} and maybe a {{TOKEN_99}} here and there.";

    let mut group = c.benchmark_group("restore_prompt_compare");
    group.bench_function("replace_approach", |b| {
        b.iter(|| replace_restore(black_box(response), black_box(&map)))
    });
    group.bench_function("aho_corasick_approach", |b| {
        b.iter(|| aho_restore(black_box(response), black_box(&map)))
    });
    group.finish();
}

criterion_group!(benches2, bench_restoration2);


fn replace_fast_restore(response: &str, map: &HashMap<String, String>) -> String {
    if map.is_empty() { return response.to_string(); }

    let mut result = String::with_capacity(response.len() + map.values().map(|v| v.len()).sum::<usize>());
    let mut last_end = 0;

    // Find all occurrences of {{TOKEN_...}}
    let token_re = Regex::new(r"\{\{TOKEN_[0-9]+\}\}").unwrap();

    for mat in token_re.find_iter(response) {
        result.push_str(&response[last_end..mat.start()]);
        let token = mat.as_str();
        if let Some(replacement) = map.get(token) {
            result.push_str(replacement);
        } else {
            result.push_str(token);
        }
        last_end = mat.end();
    }

    result.push_str(&response[last_end..]);
    result
}

fn bench_restoration3(c: &mut Criterion) {
    let mut map = HashMap::new();
    for i in 0..100 {
        map.insert(format!("{{{{TOKEN_{}}}}}", i), format!("Replacement_{}", i));
    }

    let response = "This is a response with {{TOKEN_10}} and {{TOKEN_50}} and maybe a {{TOKEN_99}} here and there.";

    let mut group = c.benchmark_group("restore_prompt_compare_all");
    group.bench_function("replace_fast_approach", |b| {
        b.iter(|| replace_fast_restore(black_box(response), black_box(&map)))
    });
    group.bench_function("aho_corasick_approach", |b| {
        b.iter(|| aho_restore(black_box(response), black_box(&map)))
    });
    group.finish();
}

criterion_group!(benches3, bench_restoration3);
criterion_main!(benches, benches2, benches3);
