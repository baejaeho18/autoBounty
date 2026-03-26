#!/usr/bin/env python3
"""--status용: 스캔/분석 디렉토리를 읽어 실시간 집계"""
import json, glob, os, sys

base = sys.argv[1]
date = sys.argv[2]
track_dir = os.path.join(base, "data", "track4")
targets_file = os.path.join(base, "data", "targets_oss.json")
llm_queue = os.path.join(track_dir, f".llm_queue_{date}.txt")
llm_done = os.path.join(track_dir, f".llm_done_{date}.txt")
status_file = os.path.join(base, ".orchestrator.status")

# 전체 타겟
try:
    with open(targets_file) as f:
        targets = json.load(f)
    total_repos = len(targets)
except:
    total_repos = 65

# Pass 1: 정적 분석 완료 수
scan_files = glob.glob(os.path.join(track_dir, "scans", f"*_redos_{date}.json"))
scanned = len(scan_files)

# 정적 분석 집계
total_findings = 0
sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
per_repo_findings = []
for sf in scan_files:
    try:
        with open(sf) as f:
            data = json.load(f)
        s = data.get("stats", {})
        total_findings += s.get("total_findings", 0)
        for k in sev:
            sev[k] += s.get(k, 0)
        name = data.get("project", os.path.basename(sf).split("_redos_")[0])
        ch = s.get("critical", 0) + s.get("high", 0)
        if ch > 0:
            per_repo_findings.append((name, s.get("critical", 0), s.get("high", 0), s.get("total_findings", 0)))
    except:
        pass

# LLM 대기열/완료
queue_count = 0
done_names = set()
try:
    with open(llm_queue) as f:
        queue_lines = [l.strip() for l in f if l.strip()]
    queue_count = len(queue_lines)
except:
    queue_lines = []

try:
    with open(llm_done) as f:
        done_names = set(l.strip() for l in f if l.strip())
except:
    pass

llm_done_count = len(done_names)
llm_pending = queue_count - llm_done_count

# LLM 분석 결과 집계
analysis_files = glob.glob(os.path.join(track_dir, "analysis", f"*_redos_{date}.json"))
tp_total = 0
fp_total = 0
tp_details = []
for af in analysis_files:
    try:
        with open(af) as f:
            data = json.load(f)
        for t in data.get("redos_triage", []):
            if t.get("verdict") == "TP":
                tp_total += 1
                tp_details.append({
                    "project": data.get("project", "?"),
                    "file": t.get("file", "?"),
                    "severity": t.get("severity", "?"),
                    "vuln_type": t.get("vuln_type", "?"),
                    "pattern": t.get("pattern", "?")[:60],
                })
            elif t.get("verdict") == "FP":
                fp_total += 1
    except:
        pass

# 리포트 수
reports = glob.glob(os.path.join(track_dir, "reports", f"*_redos_{date}_report.md"))

# 현재 상태 파일
current_status = ""
if os.path.exists(status_file):
    with open(status_file) as f:
        current_status = f.read().strip()

# ─── 출력 ───
print("══════════════════════════════════════════")
print(f"  ReDoS Scanner 진행 현황 ({date})")
print("══════════════════════════════════════════")
print()

# 현재 단계
if current_status:
    for line in current_status.split("\n"):
        print(f"  {line}")
    print()

# Pass 1
print("─── Pass 1: 정적 분석 ───────────────────")
bar_done = int((scanned / total_repos) * 30) if total_repos else 0
bar = "█" * bar_done + "░" * (30 - bar_done)
print(f"  진행: [{bar}] {scanned}/{total_repos}")
print(f"  탐지: {total_findings}건")
print(f"    CRITICAL: {sev['critical']}  HIGH: {sev['high']}  MEDIUM: {sev['medium']}  LOW: {sev['low']}")

if per_repo_findings:
    print(f"  C/H 발견 레포 ({len(per_repo_findings)}개):")
    for name, c, h, t in sorted(per_repo_findings, key=lambda x: -(x[1]+x[2]))[:10]:
        print(f"    {name}: C={c} H={h} (총 {t}건)")
    if len(per_repo_findings) > 10:
        print(f"    ... 외 {len(per_repo_findings)-10}개")
print()

# Pass 2
print("─── Pass 2: LLM 정밀 분석 ──────────────")
if queue_count == 0 and scanned < total_repos:
    print("  (Pass 1 진행 중 — 아직 미시작)")
elif queue_count == 0:
    print("  LLM 분석 대상 없음 (C/H 발견 0건)")
else:
    bar_done2 = int((llm_done_count / queue_count) * 30) if queue_count else 0
    bar2 = "█" * bar_done2 + "░" * (30 - bar_done2)
    print(f"  진행: [{bar2}] {llm_done_count}/{queue_count}")
    print(f"  판정: TP(진양성) {tp_total}건 / FP(오탐) {fp_total}건")
    if llm_pending > 0:
        print(f"  대기: {llm_pending}개 프로젝트 남음")

if tp_details:
    print(f"  TP 상세:")
    for d in tp_details[:8]:
        print(f"    [{d['severity']}] {d['project']} → {d['file']}")
        print(f"           {d['vuln_type']}: {d['pattern']}")
    if len(tp_details) > 8:
        print(f"    ... 외 {len(tp_details)-8}건")
print()

# 리포트
print("─── 리포트 ─────────────────────────────")
print(f"  생성: {len(reports)}건")
for r in reports:
    print(f"    {os.path.basename(r)}")
print()
