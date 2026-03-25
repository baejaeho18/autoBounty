#!/usr/bin/env python3
"""
ReDoS Scanner 진행 상황 모니터.

사용법:
  python3 scripts/status.py              # 전체 진행 상황 요약
  python3 scripts/status.py --detail     # 프로젝트별 상세 현황
  python3 scripts/status.py --findings   # 발견사항만 요약
  python3 scripts/status.py --project angular_angular  # 특정 프로젝트 상세
"""
import json
import os
import sys
import argparse
import glob
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
TARGETS_FILE = os.path.join(BASE_DIR, "data", "targets_oss.json")
TRACK_DIR = os.path.join(BASE_DIR, "data", "track4")
FINDINGS_DB = os.path.join(BASE_DIR, "data", "findings.json")

COLORS = {
    "CRITICAL": "\033[91m", "HIGH": "\033[93m",
    "MEDIUM": "\033[96m", "LOW": "\033[37m",
    "GREEN": "\033[92m", "DIM": "\033[2m",
    "BOLD": "\033[1m", "RESET": "\033[0m",
}

C = COLORS


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except:
        return None


def get_targets():
    data = load_json(TARGETS_FILE)
    return data if data else []


def get_repo_status(name):
    """레포의 스캔 상태 확인"""
    repo_dir = os.path.join(TRACK_DIR, "repos", name)
    scan_pattern = os.path.join(TRACK_DIR, "scans", f"{name}_redos_*.json")
    analysis_pattern = os.path.join(TRACK_DIR, "analysis", f"{name}_redos_*.json")
    report_pattern = os.path.join(TRACK_DIR, "reports", f"{name}_redos_*_report.md")

    status = {
        "cloned": os.path.isdir(os.path.join(repo_dir, ".git")) if os.path.isdir(repo_dir) else False,
        "scan_files": sorted(glob.glob(scan_pattern)),
        "analysis_files": sorted(glob.glob(analysis_pattern)),
        "report_files": sorted(glob.glob(report_pattern)),
    }

    # 최신 스캔 결과 로드
    status["latest_scan"] = None
    if status["scan_files"]:
        status["latest_scan"] = load_json(status["scan_files"][-1])

    # 최신 분석 결과 로드
    status["latest_analysis"] = None
    if status["analysis_files"]:
        status["latest_analysis"] = load_json(status["analysis_files"][-1])

    return status


def print_overview():
    """전체 진행 상황 요약"""
    targets = get_targets()
    if not targets:
        print(f"\n  대상 레포 없음. 먼저 python3 scripts/fetch_oss_repos.py 실행\n")
        return

    total = len(targets)
    cloned = 0
    scanned = 0
    analyzed = 0
    reported = 0
    total_findings = 0
    critical_findings = 0
    high_findings = 0
    tp_count = 0

    tier_stats = {"TIER_OT0": {"total": 0, "scanned": 0}, "TIER_OT1": {"total": 0, "scanned": 0}}

    for t in targets:
        name = t["name"]
        tier = t.get("tier", "UNKNOWN")
        if tier in tier_stats:
            tier_stats[tier]["total"] += 1

        st = get_repo_status(name)
        if st["cloned"]:
            cloned += 1
        if st["scan_files"]:
            scanned += 1
            if tier in tier_stats:
                tier_stats[tier]["scanned"] += 1
        if st["analysis_files"]:
            analyzed += 1
        if st["report_files"]:
            reported += 1

        if st["latest_scan"]:
            stats = st["latest_scan"].get("stats", {})
            total_findings += stats.get("total_findings", 0)
            critical_findings += stats.get("critical", 0)
            high_findings += stats.get("high", 0)

        if st["latest_analysis"]:
            triage = st["latest_analysis"].get("redos_triage", [])
            tp_count += len([t for t in triage if t.get("verdict") == "TP"])

    # 출력
    print(f"\n  {C['BOLD']}ReDoS Scanner 진행 상황{C['RESET']}")
    print(f"  {'='*55}")

    # 진행률 바
    pct = (scanned / total * 100) if total > 0 else 0
    bar_len = 30
    filled = int(bar_len * scanned / total) if total > 0 else 0
    bar = "█" * filled + "░" * (bar_len - filled)
    print(f"\n  진행률: [{bar}] {scanned}/{total} ({pct:.0f}%)")

    print(f"\n  {C['BOLD']}단계별 현황:{C['RESET']}")
    print(f"    Clone 완료:    {cloned}/{total}")
    print(f"    정적 스캔:     {scanned}/{total}")
    print(f"    LLM 분석:      {analyzed}/{scanned if scanned else total} (CRITICAL/HIGH 대상)")
    print(f"    리포트 생성:   {reported}건")

    print(f"\n  {C['BOLD']}티어별:{C['RESET']}")
    for tier, ts in tier_stats.items():
        print(f"    {tier}: {ts['scanned']}/{ts['total']} 스캔 완료")

    print(f"\n  {C['BOLD']}발견 현황 (정적 분석):{C['RESET']}")
    print(f"    총 발견:       {total_findings}건")
    print(f"    {C['CRITICAL']}CRITICAL:      {critical_findings}건{C['RESET']}")
    print(f"    {C['HIGH']}HIGH:          {high_findings}건{C['RESET']}")

    if tp_count > 0:
        print(f"\n  {C['BOLD']}LLM 판별:{C['RESET']}")
        print(f"    {C['GREEN']}True Positive:  {tp_count}건{C['RESET']}")

    # findings.json 기반 통계
    fdb = load_json(FINDINGS_DB)
    if fdb:
        redos_findings = [f for f in fdb.get("findings", []) if f.get("track") == "redos"]
        if redos_findings:
            pending = len([f for f in redos_findings if f["status"] == "pending_review"])
            verified = len([f for f in redos_findings if f["status"] == "verified"])
            submitted = len([f for f in redos_findings if f["status"] == "submitted"])
            print(f"\n  {C['BOLD']}검증 상태:{C['RESET']}")
            print(f"    대기 중:       {pending}건")
            print(f"    검증 완료:     {verified}건")
            print(f"    제출 완료:     {submitted}건")

    if reported > 0:
        print(f"\n  {C['BOLD']}리포트 위치:{C['RESET']}")
        print(f"    data/track4/reports/")

    print(f"\n  {C['BOLD']}다음 단계:{C['RESET']}")
    if scanned == 0:
        print(f"    실행: bash scripts/track4_redos.sh")
    elif tp_count > 0:
        print(f"    1. 결과 확인: python3 scripts/review.py")
        print(f"    2. 리포트 보기: python3 scripts/review.py --show [번호]")
        print(f"    3. 수동 검증 후: python3 scripts/review.py --verify [번호]")
    else:
        print(f"    파이프라인 실행 중이거나, 아직 TP가 발견되지 않았습니다.")

    print()


def print_detail():
    """프로젝트별 상세 현황"""
    targets = get_targets()
    if not targets:
        print(f"\n  대상 레포 없음\n")
        return

    print(f"\n  {C['BOLD']}프로젝트별 상세 현황{C['RESET']}")
    print(f"  {'='*80}")
    print(f"  {'프로젝트':<30} {'티어':8} {'Clone':6} {'스캔':6} {'발견':6} {'C/H':6} {'TP':4} {'리포트':6}")
    print(f"  {'─'*30} {'─'*8} {'─'*6} {'─'*6} {'─'*6} {'─'*6} {'─'*4} {'─'*6}")

    for t in targets:
        name = t["name"]
        tier = t.get("tier", "?")[:8]
        st = get_repo_status(name)

        clone_mark = "O" if st["cloned"] else "-"
        scan_mark = "O" if st["scan_files"] else "-"

        findings = "-"
        ch = "-"
        tp = "-"
        report_mark = "-"

        if st["latest_scan"]:
            stats = st["latest_scan"].get("stats", {})
            total_f = stats.get("total_findings", 0)
            c = stats.get("critical", 0)
            h = stats.get("high", 0)
            findings = str(total_f)
            ch = str(c + h) if (c + h) > 0 else "-"

            if c + h > 0:
                ch = f"{C['CRITICAL']}{c+h}{C['RESET']}"

        if st["latest_analysis"]:
            triage = st["latest_analysis"].get("redos_triage", [])
            tp_list = [x for x in triage if x.get("verdict") == "TP"]
            if tp_list:
                tp = f"{C['GREEN']}{len(tp_list)}{C['RESET']}"

        if st["report_files"]:
            report_mark = f"{C['GREEN']}O{C['RESET']}"

        print(f"  {name:<30} {tier:8} {clone_mark:6} {scan_mark:6} {findings:6} {ch:6} {tp:4} {report_mark:6}")

    print()


def print_findings_summary():
    """발견사항만 요약"""
    targets = get_targets()

    print(f"\n  {C['BOLD']}ReDoS 발견사항 요약{C['RESET']}")
    print(f"  {'='*70}")

    found_any = False
    for t in targets:
        name = t["name"]
        st = get_repo_status(name)

        if not st["latest_scan"]:
            continue

        scan = st["latest_scan"]
        findings = scan.get("findings", [])
        if not findings:
            continue

        # CRITICAL/HIGH만 표시
        important = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
        if not important:
            continue

        found_any = True
        print(f"\n  {C['BOLD']}{name}{C['RESET']} ({t.get('language', '?')})")

        for f in important:
            sev_c = C.get(f["severity"], "")
            tp_mark = ""
            if st["latest_analysis"]:
                triage = st["latest_analysis"].get("redos_triage", [])
                matching = [x for x in triage
                            if x.get("file", "").startswith(f["file"].split(":")[0])
                            and x.get("pattern") == f.get("pattern")]
                if matching:
                    verdict = matching[0].get("verdict", "?")
                    if verdict == "TP":
                        tp_mark = f" {C['GREEN']}[TP]{C['RESET']}"
                    else:
                        tp_mark = f" {C['DIM']}[FP]{C['RESET']}"

            print(f"    {sev_c}{f['severity']:8}{C['RESET']} {f['file']}:{f['line']}{tp_mark}")
            print(f"             {f['vuln_type']}: {f['pattern'][:60]}")

    if not found_any:
        print(f"\n  CRITICAL/HIGH 발견사항 없음")

    # 리포트 경로 안내
    report_files = glob.glob(os.path.join(TRACK_DIR, "reports", "*_report.md"))
    if report_files:
        print(f"\n  {C['BOLD']}생성된 리포트:{C['RESET']}")
        for rp in sorted(report_files):
            print(f"    {os.path.relpath(rp, BASE_DIR)}")

    print(f"\n  {C['BOLD']}상세 검증 방법:{C['RESET']}")
    print(f"    1. 리포트 확인:   cat data/track4/reports/<project>_redos_<date>_report.md")
    print(f"    2. 스캔 원본:     cat data/track4/scans/<project>_redos_<date>.json")
    print(f"    3. LLM 분석:      cat data/track4/analysis/<project>_redos_<date>.json")
    print(f"    4. 수동 재현:     취약 정규식에 공격 입력을 넣어 CPU 소모 확인")
    print(f"    5. 상태 관리:     python3 scripts/review.py --verify [번호]")
    print()


def print_project_detail(project_name):
    """특정 프로젝트 상세"""
    st = get_repo_status(project_name)

    print(f"\n  {C['BOLD']}프로젝트: {project_name}{C['RESET']}")
    print(f"  {'='*60}")

    print(f"\n  Clone: {'완료' if st['cloned'] else '미완료'}")

    if st["scan_files"]:
        print(f"  스캔 파일: {len(st['scan_files'])}개")
        for sf in st["scan_files"]:
            print(f"    {os.path.relpath(sf, BASE_DIR)}")

    if st["latest_scan"]:
        scan = st["latest_scan"]
        stats = scan.get("stats", {})
        print(f"\n  {C['BOLD']}최신 스캔 결과 ({scan.get('scan_date', '?')}):{C['RESET']}")
        print(f"    파일 스캔:   {stats.get('files_scanned', 0)}개")
        print(f"    총 발견:     {stats.get('total_findings', 0)}건")
        print(f"    CRITICAL:    {stats.get('critical', 0)}")
        print(f"    HIGH:        {stats.get('high', 0)}")
        print(f"    MEDIUM:      {stats.get('medium', 0)}")
        print(f"    LOW:         {stats.get('low', 0)}")

        findings = scan.get("findings", [])
        if findings:
            print(f"\n  {C['BOLD']}발견 목록:{C['RESET']}")
            for f in findings:
                sev_c = C.get(f["severity"], "")
                print(f"    {sev_c}{f['severity']:8}{C['RESET']} {f['file']}:{f['line']}")
                print(f"             Type: {f['vuln_type']}")
                print(f"             Pattern: {f['pattern'][:80]}")
                print(f"             {f['description']}")
                print()

    if st["latest_analysis"]:
        analysis = st["latest_analysis"]
        triage = analysis.get("redos_triage", [])
        if triage:
            print(f"\n  {C['BOLD']}LLM 분석 결과:{C['RESET']}")
            for t in triage:
                v_c = C["GREEN"] if t.get("verdict") == "TP" else C["DIM"]
                print(f"    {v_c}{t.get('verdict', '?')}{C['RESET']} {t.get('file', '?')}")
                print(f"         Confidence: {t.get('confidence', '?')}")
                print(f"         {t.get('reasoning', '')[:120]}")
                if t.get("verdict") == "TP" and t.get("attack_input"):
                    print(f"         Attack: {t.get('attack_input', '')[:80]}")
                print()

    if st["report_files"]:
        print(f"\n  {C['BOLD']}리포트:{C['RESET']}")
        for rp in st["report_files"]:
            print(f"    {os.path.relpath(rp, BASE_DIR)}")

    print()


def main():
    parser = argparse.ArgumentParser(description="ReDoS Scanner 진행 상황 모니터")
    parser.add_argument("--detail", "-d", action="store_true", help="프로젝트별 상세 현황")
    parser.add_argument("--findings", "-f", action="store_true", help="발견사항 요약")
    parser.add_argument("--project", "-p", default="", help="특정 프로젝트 상세")
    args = parser.parse_args()

    if args.project:
        print_project_detail(args.project)
    elif args.findings:
        print_findings_summary()
    elif args.detail:
        print_detail()
    else:
        print_overview()


if __name__ == "__main__":
    main()
