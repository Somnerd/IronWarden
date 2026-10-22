#!/usr/bin/env python3
"""
IronWarden — Historical Benchmark & Test Tracker
=================================================
Automates test execution, Criterion microbenchmarking, and accuracy evaluation,
aggregating longitudinal telemetry into a persistent, date/time-indexed CSV.

Features:
  - Executes cargo test, cargo bench, and iw-accuracy-suite.
  - Automatically parses Criterion estimates (mean/median in ns/µs).
  - Extracts empirical PII Shield accuracy, recall, and F1 across CoNLL, WikiGold,
    the 100k multilingual matrix, and adversarial enterprise slices.
  - Appends structured rows with ISO-8601 timestamps and Git metadata to CSV.
  - Provides instant terminal delta comparisons against previous runs.
"""

import argparse
import csv
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CSV_PATH = REPO_ROOT / "benchmarks" / "history" / "benchmark_history.csv"
LOGS_DIR = REPO_ROOT / "target" / "logs"

CSV_FIELDNAMES = [
    # Metadata & Provenance
    "timestamp_utc",
    "date",
    "time",
    "git_commit_short",
    "git_commit_full",
    "git_branch",
    "git_dirty",
    "rustc_version",
    "run_mode",
    "tag_or_note",
    # Test Suite Metrics
    "test_status",
    "test_passed",
    "test_failed",
    "test_ignored",
    "test_total",
    "test_duration_s",
    # Criterion Microbenchmarks (Median Latencies in µs or ns)
    "crit_restore_aho_corasick_us",
    "crit_restore_regex_us",
    "crit_restore_replace_fast_us",
    "crit_shadow_ner_analyze_us",
    "crit_grounding_encrypt_ns",
    "crit_grounding_decrypt_ns",
    "crit_stream_rehydrate_none_ns",
    "crit_stream_rehydrate_tokens_ns",
    "crit_stream_rehydrate_split_ns",
    "crit_gateway_atomic_increment_ns",
    "crit_gateway_prometheus_render_ns",
    # PII Shield Accuracy & Recall Metrics
    "acc_conll2003_hyb_recall",
    "acc_conll2003_hyb_precision",
    "acc_conll2003_hyb_f1",
    "acc_conll2003_heur_recall",
    "acc_wikigold_hyb_recall",
    "acc_wikigold_hyb_precision",
    "acc_wikigold_hyb_f1",
    "acc_wikigold_heur_recall",
    "acc_100k_matrix_aggregate_recall",
    "acc_100k_matrix_duration_s",
    "acc_100k_greek_recall",
    "acc_100k_english_recall",
    "acc_100k_arabic_recall",
    "acc_100k_chinese_recall",
    "acc_eval5_5a_conversational_recall",
    "acc_eval5_5b_surnames_recall",
    "acc_eval5_5c_greek_inflected_recall",
    "acc_eval5_5d_complex_formats_recall",
    "acc_eval5_5e_negative_controls_fp_free",
    "acc_structural_financial_recall",
    "acc_structural_secret_recall",
    "acc_structural_national_id_recall",
    "acc_structural_negative_control_recall",
]


def run_command(cmd: List[str], env: Optional[Dict[str, str]] = None, log_file: Optional[Path] = None) -> Tuple[int, str]:
    """Execute command, optionally teeing output to a log file."""
    effective_env = os.environ.copy()
    if env:
        effective_env.update(env)

    # Prepend standard Rust toolchain paths
    rust_path = "/home/somnerd/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:/home/somnerd/.cargo/bin"
    if "PATH" in effective_env:
        effective_env["PATH"] = f"{rust_path}:{effective_env['PATH']}"
    else:
        effective_env["PATH"] = rust_path

    print(f"\n[RUN] {' '.join(cmd)}")
    process = subprocess.Popen(
        cmd,
        cwd=REPO_ROOT,
        env=effective_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    output_lines = []
    log_fp = None
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_fp = open(log_file, "w", encoding="utf-8")

    try:
        for line in process.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            output_lines.append(line)
            if log_fp:
                log_fp.write(line)
                log_fp.flush()
    finally:
        if log_fp:
            log_fp.close()

    process.wait()
    return process.returncode, "".join(output_lines)


def get_git_info() -> Dict[str, str]:
    """Retrieve Git commit, branch, and status."""
    info = {
        "commit_short": "unknown",
        "commit_full": "unknown",
        "branch": "unknown",
        "dirty": "unknown",
    }
    try:
        r = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True)
        if r.returncode == 0:
            info["commit_short"] = r.stdout.strip()

        r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True)
        if r.returncode == 0:
            info["commit_full"] = r.stdout.strip()

        r = subprocess.run(["git", "branch", "--show-current"], cwd=REPO_ROOT, capture_output=True, text=True)
        if r.returncode == 0:
            info["branch"] = r.stdout.strip()

        r = subprocess.run(["git", "status", "--porcelain"], cwd=REPO_ROOT, capture_output=True, text=True)
        if r.returncode == 0:
            info["dirty"] = "dirty" if r.stdout.strip() else "clean"
    except Exception as e:
        print(f"[WARN] Failed to inspect Git metadata: {e}")
    return info


def get_rustc_version() -> str:
    """Retrieve rustc version string."""
    try:
        r = subprocess.run(["rustc", "--version"], cwd=REPO_ROOT, capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:
        pass
    return "unknown"


def parse_test_log(log_content: str) -> Dict[str, Any]:
    """Parse cargo test output for test counts and execution duration."""
    pattern = re.compile(
        r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;.*finished in ([\d\.]+)s"
    )
    total_passed = 0
    total_failed = 0
    total_ignored = 0
    total_duration = 0.0
    matched_any = False

    for match in pattern.finditer(log_content):
        matched_any = True
        total_passed += int(match.group(2))
        total_failed += int(match.group(3))
        total_ignored += int(match.group(4))
        total_duration += float(match.group(5))

    status = "N/A"
    if matched_any:
        status = "FAIL" if total_failed > 0 else "PASS"

    return {
        "test_status": status,
        "test_passed": total_passed if matched_any else "",
        "test_failed": total_failed if matched_any else "",
        "test_ignored": total_ignored if matched_any else "",
        "test_total": (total_passed + total_failed) if matched_any else "",
        "test_duration_s": round(total_duration, 2) if matched_any else "",
    }


def parse_criterion_estimates() -> Dict[str, Any]:
    """Extract median estimates from target/criterion/**/new/estimates.json."""
    crit_dir = REPO_ROOT / "target" / "criterion"
    metrics: Dict[str, float] = {}

    if not crit_dir.exists():
        return {}

    for path in crit_dir.glob("**/new/estimates.json"):
        try:
            rel = path.relative_to(crit_dir).parent.parent
            bench_name = str(rel).replace("\\", "/")
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                median_ns = data.get("median", {}).get("point_estimate")
                if median_ns is not None:
                    metrics[bench_name] = float(median_ns)
        except Exception as e:
            print(f"[WARN] Failed to parse {path}: {e}")

    # Map to standardized field names
    def to_us(name: str) -> str:
        return f"{metrics[name] / 1000.0:.2f}" if name in metrics else ""

    def to_ns(name: str) -> str:
        return f"{metrics[name]:.2f}" if name in metrics else ""

    return {
        "crit_restore_aho_corasick_us": to_us("restore_prompt/aho_corasick_approach"),
        "crit_restore_regex_us": to_us("restore_prompt/regex_approach"),
        "crit_restore_replace_fast_us": to_us("restore_prompt_compare_all/replace_fast_approach"),
        "crit_shadow_ner_analyze_us": to_us("shadow_ner_analyze"),
        "crit_grounding_encrypt_ns": to_ns("grounding_crypto/encrypt_sanitized_query"),
        "crit_grounding_decrypt_ns": to_ns("grounding_crypto/decrypt_sanitized_query"),
        "crit_stream_rehydrate_none_ns": to_ns("streaming_rehydration/rehydrate_chunk_without_tokens"),
        "crit_stream_rehydrate_tokens_ns": to_ns("streaming_rehydration/rehydrate_chunk_with_complete_tokens"),
        "crit_stream_rehydrate_split_ns": to_ns("streaming_rehydration/rehydrate_split_tokens_across_chunks"),
        "crit_gateway_atomic_increment_ns": to_ns("gateway_metrics/atomic_request_increment"),
        "crit_gateway_prometheus_render_ns": to_ns("gateway_metrics/prometheus_render"),
    }


def parse_accuracy_results(acc_path: Optional[Path] = None) -> Dict[str, Any]:
    """Parse raw accuracy results JSON committed by iw-accuracy-suite."""
    path = acc_path or (REPO_ROOT / "benchmarks" / "raw" / "accuracy_eval_results.json")
    if not path.exists():
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[WARN] Failed to read accuracy JSON at {path}: {e}")
        return {}

    res: Dict[str, Any] = {}
    heur = data.get("heuristic_mode", {})
    hyb = data.get("hybrid_mode", {})
    matrix = data.get("combinatorial_100k_stress_test", {})
    eval5 = data.get("eval5_adversarial_suite", {})

    # CoNLL-2003
    conll_hyb = hyb.get("conll2003", {})
    conll_heur = heur.get("conll2003", {})
    res["acc_conll2003_hyb_recall"] = f"{conll_hyb.get('recall', 0.0):.4f}" if conll_hyb else ""
    res["acc_conll2003_hyb_precision"] = f"{conll_hyb.get('precision', 0.0):.4f}" if conll_hyb else ""
    res["acc_conll2003_hyb_f1"] = f"{conll_hyb.get('f1', 0.0):.4f}" if conll_hyb else ""
    res["acc_conll2003_heur_recall"] = f"{conll_heur.get('recall', 0.0):.4f}" if conll_heur else ""

    # WikiGold
    wiki_hyb = hyb.get("wikigold", {})
    wiki_heur = heur.get("wikigold", {})
    res["acc_wikigold_hyb_recall"] = f"{wiki_hyb.get('recall', 0.0):.4f}" if wiki_hyb else ""
    res["acc_wikigold_hyb_precision"] = f"{wiki_hyb.get('precision', 0.0):.4f}" if wiki_hyb else ""
    res["acc_wikigold_hyb_f1"] = f"{wiki_hyb.get('f1', 0.0):.4f}" if wiki_hyb else ""
    res["acc_wikigold_heur_recall"] = f"{wiki_heur.get('recall', 0.0):.4f}" if wiki_heur else ""

    # 100,000 Multilingual Matrix
    agg = matrix.get("aggregate", {})
    res["acc_100k_matrix_aggregate_recall"] = f"{agg.get('recall', 0.0):.4f}" if agg else ""
    res["acc_100k_matrix_duration_s"] = f"{matrix.get('duration_seconds', 0.0):.2f}" if "duration_seconds" in matrix else ""

    cultures = matrix.get("detailed_by_culture", {})
    res["acc_100k_greek_recall"] = f"{cultures.get('greek', {}).get('recall', 0.0):.4f}" if "greek" in cultures else ""
    res["acc_100k_english_recall"] = f"{cultures.get('english', {}).get('recall', 0.0):.4f}" if "english" in cultures else ""
    res["acc_100k_arabic_recall"] = f"{cultures.get('arabic', {}).get('recall', 0.0):.4f}" if "arabic" in cultures else ""
    res["acc_100k_chinese_recall"] = f"{cultures.get('chinese', {}).get('recall', 0.0):.4f}" if "chinese" in cultures else ""

    # EVAL 5 Slices
    slices = eval5.get("slices", {})
    res["acc_eval5_5a_conversational_recall"] = f"{slices.get('5A_CONVERSATIONAL_FULL', {}).get('recall', 0.0):.4f}" if "5A_CONVERSATIONAL_FULL" in slices else ""
    res["acc_eval5_5b_surnames_recall"] = f"{slices.get('5B_SINGLE_SURNAMES_VERBS', {}).get('recall', 0.0):.4f}" if "5B_SINGLE_SURNAMES_VERBS" in slices else ""
    res["acc_eval5_5c_greek_inflected_recall"] = f"{slices.get('5C_GREEK_INFLECTED', {}).get('recall', 0.0):.4f}" if "5C_GREEK_INFLECTED" in slices else ""
    res["acc_eval5_5d_complex_formats_recall"] = f"{slices.get('5D_COMPLEX_FORMATS', {}).get('recall', 0.0):.4f}" if "5D_COMPLEX_FORMATS" in slices else ""
    res["acc_eval5_5e_negative_controls_fp_free"] = f"{slices.get('5E_NEGATIVE_CONTROLS', {}).get('precision', 0.0):.4f}" if "5E_NEGATIVE_CONTROLS" in slices else ""

    # Structural PII
    struct = hyb.get("synthetic_structural", {})
    res["acc_structural_financial_recall"] = f"{struct.get('FINANCIAL', {}).get('recall', 0.0):.4f}" if "FINANCIAL" in struct else ""
    res["acc_structural_secret_recall"] = f"{struct.get('SECRET', {}).get('recall', 0.0):.4f}" if "SECRET" in struct else ""
    res["acc_structural_national_id_recall"] = f"{struct.get('NATIONAL_ID', {}).get('recall', 0.0):.4f}" if "NATIONAL_ID" in struct else ""
    res["acc_structural_negative_control_recall"] = f"{struct.get('NEGATIVE_CONTROL', {}).get('recall', 0.0):.4f}" if "NEGATIVE_CONTROL" in struct else ""

    return res


def load_previous_row(csv_path: Path) -> Optional[Dict[str, str]]:
    """Read the most recent entry from the CSV for comparison."""
    if not csv_path.exists():
        return None
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))
            if reader:
                return reader[-1]
    except Exception as e:
        print(f"[WARN] Could not read previous CSV rows: {e}")
    return None


def append_csv_row(csv_path: Path, row: Dict[str, Any]) -> None:
    """Append row to CSV, writing header if the file does not exist."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not csv_path.exists() or csv_path.stat().st_size == 0

    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        if write_header:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in CSV_FIELDNAMES})


def format_delta(current_val: str, prev_val: Optional[str], unit: str = "", higher_is_better: bool = False) -> str:
    """Format numerical delta between current and previous runs."""
    if not current_val or not prev_val:
        return ""
    try:
        cur = float(current_val)
        prev = float(prev_val)
        if prev == 0:
            return ""
        diff = cur - prev
        pct = (diff / prev) * 100.0

        if abs(pct) < 0.05:
            return "(stable)"

        sign = "+" if diff > 0 else ""
        delta_str = f"({sign}{pct:.1f}%)"

        if higher_is_better:
            indicator = "[+] " if diff > 0 else "[!] "
        else:
            indicator = "[-] " if diff < 0 else "[!] "

        return f"{indicator}{delta_str}"
    except ValueError:
        return ""


def print_summary(row: Dict[str, Any], prev_row: Optional[Dict[str, str]]) -> None:
    """Display an executive scorecard in the terminal."""
    print("\n" + "=" * 80)
    print("             IRONWARDEN LONGITUDINAL TELEMETRY SCORECARD")
    print("=" * 80)
    print(f"Timestamp UTC : {row.get('timestamp_utc')}  | Branch: {row.get('git_branch')} ({row.get('git_commit_short')})")
    print(f"Rustc Version : {row.get('rustc_version')}")
    if row.get("tag_or_note"):
        print(f"Note / Tag    : {row.get('tag_or_note')}")
    print("-" * 80)

    # 1. Test Suite
    if row.get("test_status"):
        prev_test = prev_row.get("test_passed") if prev_row else None
        d_test = format_delta(str(row.get("test_passed")), prev_test, higher_is_better=True)
        print(f"[TEST SUITE] Status: {row.get('test_status')} | Passed: {row.get('test_passed')} {d_test} | Failed: {row.get('test_failed')} | Ignored: {row.get('test_ignored')} | Time: {row.get('test_duration_s')}s")

    # 2. Criterion Latencies
    crit_keys = [
        ("restore_prompt (Aho-Corasick)", "crit_restore_aho_corasick_us", "µs"),
        ("restore_prompt (Replace Fast)", "crit_restore_replace_fast_us", "µs"),
        ("shadow_ner_analyze", "crit_shadow_ner_analyze_us", "µs"),
        ("grounding_crypto (Encrypt)", "crit_grounding_encrypt_ns", "ns"),
        ("grounding_crypto (Decrypt)", "crit_grounding_decrypt_ns", "ns"),
        ("sse_stream (No Tokens)", "crit_stream_rehydrate_none_ns", "ns"),
        ("sse_stream (Complete Tokens)", "crit_stream_rehydrate_tokens_ns", "ns"),
        ("sse_stream (Split Tokens)", "crit_stream_rehydrate_split_ns", "ns"),
        ("gateway_metrics (Atomic)", "crit_gateway_atomic_increment_ns", "ns"),
        ("gateway_metrics (Render)", "crit_gateway_prometheus_render_ns", "ns"),
    ]

    has_crit = any(row.get(k) for _, k, _ in crit_keys)
    if has_crit:
        print("\n[CRITERION MICROBENCHMARKS] (Median Latency)")
        for label, key, unit in crit_keys:
            val = row.get(key, "")
            if val:
                prev_val = prev_row.get(key) if prev_row else None
                delta = format_delta(val, prev_val, higher_is_better=False)
                print(f"  - {label:<32} : {val:>8} {unit}  {delta}")

    # 3. Accuracy & Recall
    acc_keys = [
        ("CoNLL-2003 Hybrid Recall", "acc_conll2003_hyb_recall"),
        ("CoNLL-2003 Hybrid F1", "acc_conll2003_hyb_f1"),
        ("WikiGold Hybrid Recall", "acc_wikigold_hyb_recall"),
        ("WikiGold Hybrid F1", "acc_wikigold_hyb_f1"),
        ("100k Matrix Aggregate Recall", "acc_100k_matrix_aggregate_recall"),
        ("100k Greek Name Recall", "acc_100k_greek_recall"),
        ("100k English Name Recall", "acc_100k_english_recall"),
        ("100k Arabic Name Recall", "acc_100k_arabic_recall"),
        ("100k Chinese Name Recall", "acc_100k_chinese_recall"),
        ("EVAL 5A Conversational Recall", "acc_eval5_5a_conversational_recall"),
        ("EVAL 5B Surnames/Verbs Recall", "acc_eval5_5b_surnames_recall"),
        ("EVAL 5C Greek Inflected Recall", "acc_eval5_5c_greek_inflected_recall"),
        ("EVAL 5D Complex Formats Recall", "acc_eval5_5d_complex_formats_recall"),
        ("EVAL 5E Negative Controls (0-FP)", "acc_eval5_5e_negative_controls_fp_free"),
    ]

    has_acc = any(row.get(k) for _, k in acc_keys)
    if has_acc:
        print("\n[PII SHIELD ACCURACY & RECALL]")
        for label, key in acc_keys:
            val = row.get(key, "")
            if val:
                try:
                    pct = float(val) * 100.0
                    val_str = f"{pct:.2f}%"
                except ValueError:
                    val_str = val
                prev_val = prev_row.get(key) if prev_row else None
                delta = format_delta(val, prev_val, higher_is_better=True)
                print(f"  - {label:<32} : {val_str:>8}  {delta}")

    print("=" * 80 + "\n")


def print_history_report(csv_path: Path, max_rows: int = 15) -> None:
    """Print a historical overview table from the CSV."""
    if not csv_path.exists():
        print(f"[ERROR] No historical CSV found at: {csv_path}")
        return

    with open(csv_path, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        print("[INFO] Historical CSV is empty.")
        return

    print(f"\n=== IronWarden Longitudinal Telemetry (Last {min(len(rows), max_rows)} entries) ===")
    print(f"Database: {csv_path}")
    print("-" * 115)
    header = f"{'Date/Time (UTC)':<20} | {'Commit':<8} | {'Tests':<10} | {'Aho-Corasick':<12} | {'ShadowNER':<10} | {'SSE Rehyd':<10} | {'CoNLL-03':<9} | {'100k Matrix':<11} | {'Tag / Note'}"
    print(header)
    print("-" * 115)

    for r in rows[-max_rows:]:
        ts = r.get("timestamp_utc", "")[:19].replace("T", " ")
        commit = r.get("git_commit_short", "")
        t_pass = f"{r.get('test_passed', '-')}/{r.get('test_total', '-')}"
        aho = f"{r.get('crit_restore_aho_corasick_us', '-')} µs" if r.get('crit_restore_aho_corasick_us') else "-"
        s_ner = f"{r.get('crit_shadow_ner_analyze_us', '-')} µs" if r.get('crit_shadow_ner_analyze_us') else "-"
        sse = f"{r.get('crit_stream_rehydrate_split_ns', '-')} ns" if r.get('crit_stream_rehydrate_split_ns') else "-"
        
        conll_raw = r.get("acc_conll2003_hyb_recall", "")
        conll = f"{float(conll_raw)*100:.1f}%" if conll_raw else "-"
        
        mat_raw = r.get("acc_100k_matrix_aggregate_recall", "")
        mat = f"{float(mat_raw)*100:.1f}%" if mat_raw else "-"
        
        note = r.get("tag_or_note", "")

        print(f"{ts:<20} | {commit:<8} | {t_pass:<10} | {aho:<12} | {s_ner:<10} | {sse:<10} | {conll:<9} | {mat:<11} | {note}")

    print("-" * 115 + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="IronWarden Historical Benchmark & Test Tracker — Aggregates date/time metrics to CSV."
    )
    parser.add_argument(
        "--mode",
        choices=["all", "test", "bench", "accuracy", "collect-only", "report"],
        default="all",
        help="Execution mode: all (run test+bench+accuracy), test, bench, accuracy, collect-only (parse existing data), or report.",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=DEFAULT_CSV_PATH,
        help=f"Target CSV file path (default: {DEFAULT_CSV_PATH})",
    )
    parser.add_argument(
        "--note",
        "--tag",
        dest="tag",
        default="",
        help="Optional tag or annotation to associate with this evaluation run.",
    )
    parser.add_argument(
        "--ner-mode",
        choices=["require_hybrid", "hybrid", "heuristic"],
        default="require_hybrid",
        help="WARDEN_NER_MODE environment variable setting (default: require_hybrid).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Max entries to show when displaying the historical report (default: 20).",
    )

    args = parser.parse_args()

    # If mode is report, simply output the historical CSV view
    if args.mode == "report":
        print_history_report(args.csv, max_rows=args.limit)
        return 0

    now = datetime.datetime.now(datetime.timezone.utc)
    git_info = get_git_info()
    rustc_ver = get_rustc_version()

    row: Dict[str, Any] = {
        "timestamp_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S"),
        "git_commit_short": git_info["commit_short"],
        "git_commit_full": git_info["commit_full"],
        "git_branch": git_info["branch"],
        "git_dirty": git_info["dirty"],
        "rustc_version": rustc_ver,
        "run_mode": args.mode,
        "tag_or_note": args.tag,
    }

    env_overrides = {"WARDEN_NER_MODE": args.ner_mode}

    # 1. Test Suite Execution
    if args.mode in ("all", "test"):
        test_log_path = LOGS_DIR / "02_test.log"
        code, output = run_command(["cargo", "test", "--workspace"], env=env_overrides, log_file=test_log_path)
        row.update(parse_test_log(output))
        if code != 0:
            row["test_status"] = "FAIL"
            print(f"[ERROR] Test suite returned non-zero exit code ({code})!")
    elif args.mode == "collect-only":
        test_log_path = LOGS_DIR / "02_test.log"
        if test_log_path.exists():
            with open(test_log_path, "r", encoding="utf-8") as f:
                row.update(parse_test_log(f.read()))

    # 2. Criterion Benchmarks Execution
    if args.mode in ("all", "bench"):
        bench_log_path = LOGS_DIR / "03_bench_criterion.log"
        code, _ = run_command(["cargo", "bench", "--workspace"], env=env_overrides, log_file=bench_log_path)
        if code != 0:
            print(f"[WARN] Criterion benchmark returned non-zero exit code ({code})!")
        row.update(parse_criterion_estimates())
    elif args.mode == "collect-only":
        row.update(parse_criterion_estimates())

    # 3. Accuracy Evaluation Execution
    if args.mode in ("all", "accuracy"):
        acc_log_path = LOGS_DIR / "04_bench_accuracy.log"
        code, _ = run_command(["bash", "scripts/bench/eval_accuracy.sh"], env=env_overrides, log_file=acc_log_path)
        if code != 0:
            print(f"[WARN] Accuracy evaluation returned non-zero exit code ({code})!")
        row.update(parse_accuracy_results())
    elif args.mode == "collect-only":
        row.update(parse_accuracy_results())

    # Load previous row for delta calculation before appending
    prev_row = load_previous_row(args.csv)

    # Append to CSV
    append_csv_row(args.csv, row)
    print(f"\n[OK] Telemetry record committed to CSV: {args.csv}")

    # Display scorecard and comparison
    print_summary(row, prev_row)
    return 0


if __name__ == "__main__":
    sys.exit(main())
