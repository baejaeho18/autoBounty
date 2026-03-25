#!/usr/bin/env python3
"""
ReDoS (Regular Expression Denial of Service) 취약점 스캐너.

소스코드에서 정규식 패턴을 추출하고, 카타스트로픽 백트래킹을 유발할 수 있는
취약한 패턴을 정적 분석으로 탐지한다.
"""
import json
import os
import re
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional


# ─── 정규식 추출 패턴 (언어별) ───

_py_re = re.compile(
    r"re\.(?:compile|match|search|sub|findall|fullmatch|split)\s*\(\s*r?[\"'](.*?)[\"']",
    re.DOTALL
)

_js_regexp_new = re.compile(
    r"new\s+RegExp\s*\(\s*[\"'`](.*?)[\"'`]",
    re.DOTALL
)

_js_regexp_literal = re.compile(
    r"(?:^|[=(:,;\[!&|?+\-~^%*/{}])\s*/(?!\*|/)((?:[^/\\\n]|\\.)+)/[gimsuy]*",
    re.MULTILINE
)

_java_pattern = re.compile(
    r'Pattern\.compile\s*\(\s*"((?:[^"\\]|\\.)*)"',
    re.DOTALL
)

_java_methods = re.compile(
    r'\.(?:matches|split|replaceAll|replaceFirst)\s*\(\s*"((?:[^"\\]|\\.)*)"',
    re.DOTALL
)

_go_regexp = re.compile(
    r'regexp\.(?:Compile|MustCompile)\s*\(\s*(?:`([^`]*)`|"((?:[^"\\]|\\.)*)")',
    re.DOTALL
)

_php_preg = re.compile(
    r"preg_(?:match|replace|match_all|split|grep)\s*\(\s*[\"'](.*?)[\"']",
    re.DOTALL
)

_ruby_regexp_new = re.compile(
    r"Regexp\.new\s*\(\s*[\"'](.*?)[\"']",
    re.DOTALL
)

_ruby_regexp_lit = re.compile(
    r"(?:^|[=(:,;\[!&|?+\-~^%*/{}])\s*/(?!\*|/)((?:[^/\\\n]|\\.)+)/[imxo]*",
    re.MULTILINE
)

_dart_regexp = re.compile(
    r"RegExp\s*\(\s*r?[\"'](.*?)[\"']",
    re.DOTALL
)

_rust_regex = re.compile(
    r'Regex::new\s*\(\s*r?"((?:[^"\\]|\\.)*)"',
    re.DOTALL
)

_rust_regex_raw = re.compile(
    r'Regex::new\s*\(\s*r#"(.*?)"#',
    re.DOTALL
)

_cpp_regex = re.compile(
    r'(?:std::)?regex\s*[({]\s*"((?:[^"\\]|\\.)*)"',
    re.DOTALL
)

_cpp_re2 = re.compile(
    r'RE2\s*\(\s*"((?:[^"\\]|\\.)*)"',
    re.DOTALL
)

REGEX_EXTRACTORS = {
    "python": [_py_re],
    "javascript": [_js_regexp_new, _js_regexp_literal],
    "typescript": [_js_regexp_new, _js_regexp_literal],
    "java": [_java_pattern, _java_methods],
    "go": [_go_regexp],
    "php": [_php_preg],
    "ruby": [_ruby_regexp_new, _ruby_regexp_lit],
    "dart": [_dart_regexp],
    "rust": [_rust_regex, _rust_regex_raw],
    "cpp": [_cpp_regex, _cpp_re2],
}

# 파일 확장자 → 언어 매핑
EXT_TO_LANG = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".mjs": "javascript", ".cjs": "javascript",
    ".java": "java", ".go": "go", ".php": "php",
    ".rb": "ruby", ".dart": "dart", ".rs": "rust",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
    ".h": "cpp", ".hpp": "cpp",
}

# 스캔 제외 디렉토리
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "third_party", "thirdparty",
    "__pycache__", ".tox", ".eggs", "dist", "build", ".build",
    "target", "out", "bin", ".gradle", ".dart_tool", ".pub-cache",
    "testdata", "test_data", "fixtures",
}

MAX_FILE_SIZE = 1_048_576  # 1MB


@dataclass
class ReDoSFinding:
    file: str
    line: int
    pattern: str
    vuln_type: str
    severity: str
    description: str
    evidence: str
    language: str
    confidence: str = "MEDIUM"

    def to_dict(self):
        return asdict(self)


# ─── ReDoS 취약 패턴 탐지 ───

def check_nested_quantifiers(pattern: str) -> Optional[tuple]:
    """중첩 수량자 탐지: (a+)+, (a*)+, (a+)*, (a{2,})+"""
    checks = [
        (r'\([^)]*[+*]\)[+*{]', "HIGH",
         "중첩 수량자: 그룹 내외 모두 수량자가 있어 지수적 백트래킹 가능"),
        (r'\([^)]*\{\d+,\d*\}\)[+*{]', "HIGH",
         "중첩 범위 수량자: 그룹 내 범위 수량자와 외부 수량자 조합"),
        (r'\([^)]*\([^)]*[+*]\)[^)]*\)[+*{]', "CRITICAL",
         "다중 중첩 수량자: 깊은 중첩으로 인한 극심한 백트래킹"),
    ]
    for pat, severity, desc in checks:
        m = re.search(pat, pattern)
        if m:
            return severity, desc, m.group(0)
    return None


def check_overlapping_alternation(pattern: str) -> Optional[tuple]:
    """겹치는 대안 + 수량자 탐지: (\d|\w)+, (a|ab)+"""
    checks = [
        (r'\((?:[^)]*\\d[^)]*\|[^)]*\\w[^)]*|[^)]*\\w[^)]*\|[^)]*\\d[^)]*)\)[+*{]',
         "MEDIUM", "겹치는 문자 클래스 대안: \\d와 \\w가 겹침"),
        (r'\((\w+)\|(\1\w+|\w+\1)\)[+*{]',
         "HIGH", "접두사가 겹치는 대안과 수량자 조합"),
        (r'\([^)]*\.\**[^)]*\|[^)]*\)[+*{]',
         "MEDIUM", "dot(.)이 다른 대안과 겹침"),
    ]
    for pat, severity, desc in checks:
        m = re.search(pat, pattern)
        if m:
            return severity, desc, m.group(0)
    return None


def check_quantified_overlap(pattern: str) -> Optional[tuple]:
    """수량자가 붙은 겹치는 그룹: (\\d+\\.?\\d*)+ 등"""
    checks = [
        (r'\(\\[dw]\+[^)]*\\[dw][*+][^)]*\)[+*{]', "HIGH",
         "수량자가 붙은 겹치는 패턴: 연속 매칭에서 분할 모호성"),
        (r'\(\.\*\?[^)]+\.\*\?\)[+*{]', "MEDIUM",
         "반복 그룹 내 lazy 수량자: 매칭 경로 폭발"),
        (r'\(\[\^[^\]]+\][*+][^)]*\)[+*{]', "MEDIUM",
         "부정 문자 클래스 수량자의 반복"),
    ]
    for pat, severity, desc in checks:
        m = re.search(pat, pattern)
        if m:
            return severity, desc, m.group(0)
    return None


def check_star_height(pattern: str) -> Optional[tuple]:
    """Star height >= 2 탐지"""
    checks = [
        (r'(?:\.\*|\.\+){2,}', "MEDIUM",
         "연속 dot 수량자: 불필요한 백트래킹 가능"),
        (r'\([^)]*\.\*[^)]*\)\*', "HIGH",
         "그룹 내 .*와 그룹 외 * 조합: star height 2"),
        (r'\([^)]*\.\+[^)]*\)\+', "HIGH",
         "그룹 내 .+와 그룹 외 + 조합: star height 2"),
    ]
    for pat, severity, desc in checks:
        m = re.search(pat, pattern)
        if m:
            return severity, desc, m.group(0)
    return None


VULN_CHECKS = [
    ("nested_quantifier", check_nested_quantifiers),
    ("overlapping_alternation", check_overlapping_alternation),
    ("quantified_overlap", check_quantified_overlap),
    ("star_height", check_star_height),
]


def _test_regex_worker(pattern_str, test_input, result_dict):
    """워커: 정규식 매칭 시도 (별도 프로세스에서 실행)"""
    import re as _re, time as _time
    start = _time.monotonic()
    try:
        compiled = _re.compile(pattern_str)
        compiled.search(test_input)
    except Exception:
        pass
    result_dict["elapsed"] = _time.monotonic() - start


def check_catastrophic_backtracking_empirical(pattern: str, timeout_sec: float = 2.0) -> Optional[tuple]:
    """경험적 검증: 별도 프로세스에서 타임아웃 기반 테스트"""
    import multiprocessing
    test_inputs = [
        "a" * 25 + "!", "0" * 25 + "!",
        "a" * 20 + "b" * 10 + "!",
        "0.0.0.0.0.0.0.0.0.0.0.0.0.0!",
    ]
    try:
        re.compile(pattern)
    except re.error:
        return None

    for test_input in test_inputs:
        manager = multiprocessing.Manager()
        result_dict = manager.dict()
        result_dict["elapsed"] = -1.0

        proc = multiprocessing.Process(
            target=_test_regex_worker,
            args=(pattern, test_input, result_dict)
        )
        proc.start()
        proc.join(timeout=timeout_sec)

        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=1)
            return ("CRITICAL",
                    f"경험적 검증: 입력 길이 {len(test_input)}에 대해 {timeout_sec}초 내 완료 안됨 (타임아웃)",
                    f"Input: {test_input[:50]}...")

        elapsed = result_dict.get("elapsed", -1.0)
        if elapsed > 0.5:
            severity = "CRITICAL" if elapsed > 1.5 else "HIGH"
            return (severity,
                    f"경험적 검증: 입력 길이 {len(test_input)}에 대해 {elapsed:.2f}초 소요",
                    f"Input: {test_input[:50]}...")
    return None


# ─── 파일/디렉토리 스캔 ───

def extract_regexes_from_file(filepath: str, language: str) -> list:
    """파일에서 정규식 패턴과 라인 번호를 추출"""
    results = []
    extractors = REGEX_EXTRACTORS.get(language, [])
    if not extractors:
        return results

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (OSError, IOError):
        return results

    for extractor in extractors:
        for match in extractor.finditer(content):
            pattern = None
            for g in match.groups():
                if g is not None:
                    pattern = g
                    break
            if not pattern or len(pattern) < 3:
                continue
            line_start = content[:match.start()].count("\n") + 1
            results.append((line_start, pattern))

    return results


def analyze_pattern(pattern: str) -> list:
    """단일 정규식 패턴에 대해 모든 취약점 체크 실행"""
    findings = []
    for check_name, check_fn in VULN_CHECKS:
        result = check_fn(pattern)
        if result:
            severity, description, evidence = result
            findings.append((check_name, severity, description, evidence))
    return findings


def scan_file(filepath: str, language: str) -> list:
    """단일 파일 스캔"""
    findings = []
    regexes = extract_regexes_from_file(filepath, language)

    for line_num, pattern in regexes:
        vulns = analyze_pattern(pattern)
        for vuln_type, severity, description, evidence in vulns:
            findings.append(ReDoSFinding(
                file=filepath, line=line_num, pattern=pattern,
                vuln_type=vuln_type, severity=severity,
                description=description, evidence=evidence,
                language=language,
            ))

    # HIGH/CRITICAL에 대해 경험적 검증
    for line_num, pattern in regexes:
        static_found = any(
            f.line == line_num and f.pattern == pattern for f in findings
        )
        if static_found:
            emp = check_catastrophic_backtracking_empirical(pattern)
            if emp:
                severity, description, evidence = emp
                findings.append(ReDoSFinding(
                    file=filepath, line=line_num, pattern=pattern,
                    vuln_type="empirical_backtracking", severity=severity,
                    description=description, evidence=evidence,
                    language=language, confidence="HIGH",
                ))

    return findings


def scan_directory(repo_dir: str, project_name: str = "") -> dict:
    """디렉토리 전체를 스캔하여 ReDoS 취약점 탐지"""
    all_findings = []
    scanned_files = 0
    skipped_files = 0
    repo_path = Path(repo_dir)

    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            filepath = os.path.join(root, filename)
            ext = os.path.splitext(filename)[1].lower()
            if ext not in EXT_TO_LANG:
                continue
            try:
                if os.path.getsize(filepath) > MAX_FILE_SIZE:
                    skipped_files += 1
                    continue
            except OSError:
                continue

            language = EXT_TO_LANG[ext]
            scanned_files += 1
            file_findings = scan_file(filepath, language)

            for f in file_findings:
                try:
                    f.file = str(Path(f.file).relative_to(repo_path))
                except ValueError:
                    pass
            all_findings.extend(file_findings)

    # 중복 제거
    seen = set()
    unique = []
    for f in all_findings:
        key = (f.file, f.line, f.pattern, f.vuln_type)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    unique.sort(key=lambda f: severity_order.get(f.severity, 4))

    return {
        "project": project_name or os.path.basename(repo_dir),
        "scan_date": time.strftime("%Y-%m-%d"),
        "scan_type": "redos_static_analysis",
        "stats": {
            "files_scanned": scanned_files,
            "files_skipped": skipped_files,
            "total_findings": len(unique),
            "critical": sum(1 for f in unique if f.severity == "CRITICAL"),
            "high": sum(1 for f in unique if f.severity == "HIGH"),
            "medium": sum(1 for f in unique if f.severity == "MEDIUM"),
            "low": sum(1 for f in unique if f.severity == "LOW"),
        },
        "findings": [f.to_dict() for f in unique],
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="ReDoS 취약점 스캐너")
    parser.add_argument("repo_dir", help="스캔할 레포지토리 디렉토리")
    parser.add_argument("--name", "-n", default="", help="프로젝트 이름")
    parser.add_argument("--output", "-o", default="", help="결과 JSON 파일 경로")
    parser.add_argument("--min-severity", "-s", default="LOW",
                        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        help="최소 심각도 필터")
    args = parser.parse_args()

    if not os.path.isdir(args.repo_dir):
        print(f"ERROR: 디렉토리 없음 — {args.repo_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"[redos_scanner] 스캔 시작: {args.repo_dir}", file=sys.stderr)
    result = scan_directory(args.repo_dir, args.name)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    min_level = severity_order.get(args.min_severity, 3)
    result["findings"] = [
        f for f in result["findings"]
        if severity_order.get(f["severity"], 4) <= min_level
    ]

    stats = result["stats"]
    print(f"[redos_scanner] 완료: {stats['files_scanned']}개 파일, "
          f"{stats['total_findings']}건 발견 "
          f"(C:{stats['critical']} H:{stats['high']} "
          f"M:{stats['medium']} L:{stats['low']})", file=sys.stderr)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"[redos_scanner] 결과 저장: {args.output}", file=sys.stderr)
    else:
        json.dump(result, sys.stdout, indent=2, ensure_ascii=False)
        print()


if __name__ == "__main__":
    main()
