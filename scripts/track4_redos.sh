#!/usr/bin/env bash
# ============================================================
# Track 4: ReDoS (Regular Expression Denial of Service) 취약점 스캐너
# Google Bug Hunters OSS VRP 대상 레포지토리를 스캔
#
# 파이프라인:
#   1. 레포 목록 가져오기 (Google Bug Hunters txtpb 파싱)
#   2. 각 레포 Clone/Pull
#   3. 정적 분석으로 위험한 정규식 탐지
#   4. LLM 정밀 분석 (TP/FP 판별)
#   5. 리포트 생성 → git commit & push → Discord 알림
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$(dirname "$SCRIPT_DIR")"
TRACK_DIR="$BASE/data/track4"
TARGETS="$BASE/data/targets_oss.json"
CONFIG="$BASE/config.json"
EXTRACT_JSON="$BASE/scripts/extract_json.py"
REDOS_SCANNER="$BASE/scripts/redos_scanner.py"
FETCH_REPOS="$BASE/scripts/fetch_oss_repos.py"
NOTIFY_DISCORD="$BASE/scripts/notify_discord.py"
DATE=$(date +%Y-%m-%d)
BRANCH=$(git -C "$BASE" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")

mkdir -p "$TRACK_DIR"/{repos,scans,analysis,reports}

log() { echo "[T4 $(date '+%H:%M:%S')] $1"; }

# ──────────────────────────────────────
# 헬퍼: 리포트 git commit + push (재시도 포함)
# ──────────────────────────────────────
commit_and_push_report() {
  local report_file="$1"
  local project_name="$2"

  local rel_path
  rel_path=$(python3 -c "import os; print(os.path.relpath('$report_file', '$BASE'))")

  git -C "$BASE" add "$rel_path"
  git -C "$BASE" commit -m "Add ReDoS report: ${project_name} (${DATE})" 2>/dev/null || {
    log "WARN: git commit 실패 (변경 없음?)"
    return 1
  }

  # push with exponential backoff retry
  local attempt=0
  local wait_sec=2
  while [[ $attempt -lt 4 ]]; do
    if git -C "$BASE" push -u origin "$BRANCH" 2>/dev/null; then
      log "git push 완료: $rel_path"
      return 0
    fi
    attempt=$((attempt + 1))
    log "WARN: git push 실패 (시도 $attempt/4) — ${wait_sec}초 후 재시도"
    sleep $wait_sec
    wait_sec=$((wait_sec * 2))
  done
  log "ERROR: git push 4회 실패"
  return 1
}

# ──────────────────────────────────────
# Phase 0: 레포 목록 업데이트
# ──────────────────────────────────────
log "Phase 0: Google Bug Hunters OSS VRP 레포 목록 가져오기"
python3 "$FETCH_REPOS" || {
  log "WARN: 레포 목록 갱신 실패 — 기존 목록 사용"
}

# 타겟 수 확인
TARGET_COUNT=$(python3 -c "
import json
with open('$TARGETS') as f:
    print(len(json.load(f)))
" 2>/dev/null || echo "0")

if [[ "$TARGET_COUNT" == "0" ]]; then
  log "등록된 OSS 타겟 없음 — 종료"
  exit 0
fi

log "총 ${TARGET_COUNT}개 레포 대상 ReDoS 스캔 시작"

# ──────────────────────────────────────
# 레포별 스캔 루프
# ──────────────────────────────────────
TOTAL_FINDINGS=0
SCANNED_REPOS=0
FAILED_REPOS=0

python3 -c "
import json
with open('$TARGETS') as f:
    targets = json.load(f)
for t in targets:
    print(f\"{t['repo_url']}|{t['name']}|{t.get('language','unknown')}|{t.get('tier','UNKNOWN')}\")
" | while IFS='|' read -r REPO_URL NAME LANG TIER; do

  log "=== [$TIER] $NAME ($LANG) ReDoS 스캔 시작 ==="
  REPO_DIR="$TRACK_DIR/repos/$NAME"

  # ──────────────────────────────────────
  # Phase 1: Clone 또는 Pull
  # ──────────────────────────────────────
  if [[ -d "$REPO_DIR/.git" ]]; then
    log "Phase 1: git pull (기존 레포)"
    git -C "$REPO_DIR" pull --quiet 2>/dev/null || {
      log "WARN: git pull 실패 ($NAME) — 기존 코드로 계속"
    }
  else
    log "Phase 1: git clone --depth 1 (신규)"
    if ! git clone --depth 1 "$REPO_URL" "$REPO_DIR" 2>/dev/null; then
      log "ERROR: git clone 실패 ($NAME) — 스킵"
      FAILED_REPOS=$((FAILED_REPOS + 1))
      continue
    fi
  fi

  # ──────────────────────────────────────
  # Phase 2: 정적 ReDoS 스캔
  # ──────────────────────────────────────
  SCAN_FILE="$TRACK_DIR/scans/${NAME}_redos_${DATE}.json"

  log "Phase 2: ReDoS 정적 분석 스캔"
  if python3 "$REDOS_SCANNER" "$REPO_DIR" \
      --name "$NAME" \
      --output "$SCAN_FILE" \
      --min-severity LOW 2>/dev/null; then

    FINDING_COUNT=$(python3 -c "
import json
try:
    with open('$SCAN_FILE') as f:
        data = json.load(f)
    print(data.get('stats', {}).get('total_findings', 0))
except: print(0)
" 2>/dev/null || echo "0")

    CRIT_HIGH=$(python3 -c "
import json
try:
    with open('$SCAN_FILE') as f:
        data = json.load(f)
    s = data.get('stats', {})
    print(s.get('critical', 0) + s.get('high', 0))
except: print(0)
" 2>/dev/null || echo "0")

    log "정적 스캔 완료: ${FINDING_COUNT}건 발견 (CRITICAL+HIGH: ${CRIT_HIGH}건)"
  else
    log "WARN: ReDoS 스캐너 실패 ($NAME)"
    continue
  fi

  # ──────────────────────────────────────
  # Phase 3: LLM 정밀 분석 (CRITICAL/HIGH만)
  # ──────────────────────────────────────
  ANALYSIS_FILE="$TRACK_DIR/analysis/${NAME}_redos_${DATE}.json"
  ALLOWED_TOOLS="Read,Grep,Glob,Bash(ls:*),Bash(head:*),Bash(wc:*),Bash(find:*),Bash(python3:*)"

  if [[ "$CRIT_HIGH" -gt 0 ]]; then
    log "Phase 3: LLM 정밀 분석 (${CRIT_HIGH}건 TP/FP 판별)"

    # 스캔 결과 요약 생성
    SCAN_SUMMARY=$(python3 - "$SCAN_FILE" <<'PYEOF'
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except:
    print("스캔 결과 없음"); sys.exit(0)

findings = [f for f in data.get("findings", []) if f.get("severity") in ("CRITICAL", "HIGH")]
if not findings:
    print("CRITICAL/HIGH 결과 0건"); sys.exit(0)

for f in findings[:30]:
    print(f"- [{f['severity']}] {f['vuln_type']} → {f['file']}:{f['line']}")
    print(f"  Pattern: {f['pattern'][:100]}")
    print(f"  Evidence: {f['evidence'][:80]}")
    print(f"  Description: {f['description']}")
    print()
PYEOF
    )

    claude -p "
당신은 시니어 보안 연구원입니다. $NAME ($LANG) 프로젝트의 ReDoS 취약점을 정밀 분석합니다.

프로젝트 경로: $REPO_DIR

## 정적 분석으로 탐지된 ReDoS 후보:
$SCAN_SUMMARY

**지시사항:**
1. 위 각 탐지 항목의 파일을 Read 도구로 직접 열어서 전체 코드 컨텍스트를 확인하세요
2. 해당 정규식이 실제로 외부 입력(사용자 입력, HTTP 요청, 파일 입력 등)에 노출되는지 추적하세요
3. Grep으로 해당 정규식을 사용하는 함수가 어디서 호출되는지 확인하세요
4. 입력 길이 제한, 타임아웃, 선형 시간 정규식 엔진(RE2 등) 사용 여부를 확인하세요

**TP (True Positive) 판별 기준:**
- 외부 입력이 검증 없이 취약한 정규식에 도달
- 입력 길이 제한이 없거나 충분히 크다 (>100자)
- 타임아웃 메커니즘이 없다
- 백트래킹 기반 정규식 엔진 사용 (Python re, Java Pattern, JS RegExp 등)
  ※ Go의 regexp 패키지는 RE2 기반이라 ReDoS에 안전 — FP로 판별

**FP (False Positive) 판별 기준:**
- RE2 또는 선형 시간 엔진 사용
- 내부 전용 코드이고 외부 입력이 닿지 않음
- 입력이 이미 길이 제한/검증됨
- 테스트 코드에서만 사용
- 정규식이 실제로는 위험하지 않음 (정적 분석 오탐)

최종 결과를 반드시 아래 JSON 형식으로만 출력하세요:
{
  \"project\": \"$NAME\",
  \"date\": \"$DATE\",
  \"redos_triage\": [
    {
      \"file\": \"파일:라인\",
      \"pattern\": \"정규식 패턴\",
      \"verdict\": \"TP 또는 FP\",
      \"confidence\": \"HIGH/MEDIUM/LOW\",
      \"severity\": \"CRITICAL/HIGH/MEDIUM/LOW\",
      \"vuln_type\": \"nested_quantifier/overlapping_alternation/etc\",
      \"reasoning\": \"판별 근거 (어떤 파일의 어떤 코드를 확인했는지 포함)\",
      \"attack_input\": \"TP일 때: ReDoS를 유발하는 입력 예시\",
      \"attack_scenario\": \"TP일 때: 구체적 공격 시나리오\",
      \"cwe\": \"CWE-1333\"
    }
  ]
}
" --allowedTools "$ALLOWED_TOOLS" 2>/dev/null | python3 "$EXTRACT_JSON" > "$ANALYSIS_FILE"

    # TP 건수 확인
    TP_COUNT=$(python3 -c "
import json
try:
    with open('$ANALYSIS_FILE') as f:
        data = json.load(f)
    tp = [t for t in data.get('redos_triage', []) if t.get('verdict') == 'TP']
    print(len(tp))
except: print(0)
" 2>/dev/null || echo "0")

    log "LLM 분석 완료: TP ${TP_COUNT}건"

  else
    log "Phase 3: CRITICAL/HIGH 없음 — LLM 분석 스킵"
  fi

  # ──────────────────────────────────────
  # Phase 4: 리포트 생성 → commit & push → Discord 알림
  # ──────────────────────────────────────
  if [[ -f "$ANALYSIS_FILE" ]]; then
    TP_HIGH_COUNT=$(python3 -c "
import json
try:
    with open('$ANALYSIS_FILE') as f:
        data = json.load(f)
    tp = [t for t in data.get('redos_triage', [])
          if t.get('verdict') == 'TP' and t.get('severity') in ('CRITICAL', 'HIGH')
          and t.get('confidence') in ('HIGH', 'MEDIUM')]
    print(len(tp))
except: print(0)
" 2>/dev/null || echo "0")

    if [[ "$TP_HIGH_COUNT" -gt 0 ]]; then
      log "Phase 4: ReDoS 리포트 생성 (TP CRITICAL/HIGH: ${TP_HIGH_COUNT}건)"

      ANALYSIS_CONTENT=$(cat "$ANALYSIS_FILE")
      REPORT_FILE="$TRACK_DIR/reports/${NAME}_redos_${DATE}_report.md"

      claude -p "
아래 ReDoS 취약점 분석 결과를 바탕으로 Responsible Disclosure 리포트를 작성하세요.
TP(True Positive)로 판별된 HIGH/CRITICAL 건만 포함합니다.

$ANALYSIS_CONTENT

형식:
# ReDoS Vulnerability Report: $NAME
## Summary
- 발견된 ReDoS 취약점 수, 심각도 분포
## Methodology
- Static regex pattern analysis (nested quantifiers, overlapping alternations)
- LLM-assisted triage (TP/FP classification with code context analysis)
- Empirical backtracking verification
## Vulnerability Details (각 TP CRITICAL/HIGH 건에 대해)
### [CWE-1333] ReDoS in [파일명]
- **Severity**: [CVSS 3.1 점수] — CWE-1333: Inefficient Regular Expression Complexity
- **File**: [파일:라인]
- **Vulnerable Pattern**: \`정규식\`
- **Description**: 취약점 상세 설명
- **Attack Input**: ReDoS를 유발하는 구체적 입력
- **Steps to Reproduce**:
  1. 구체적 재현 단계
- **Impact**: CPU exhaustion, denial of service
- **Suggested Fix**: 수정 제안 (안전한 정규식 또는 RE2 사용 등)
## Timeline
- Discovered: $DATE
- Vendor notification: [TBD]
" > "$REPORT_FILE" 2>/dev/null

      if [[ -s "$REPORT_FILE" ]]; then
        # findings.json에 추가
        python3 - "$ANALYSIS_FILE" "$NAME" "$REPORT_FILE" "$BASE" <<'PYEOF'
import json, sys, os

analysis_file, name, report_file, base_dir = sys.argv[1:5]

try:
    with open(analysis_file) as f:
        data = json.load(f)
except:
    sys.exit(0)

tp_findings = [
    t for t in data.get("redos_triage", [])
    if t.get("verdict") == "TP" and t.get("severity") in ("CRITICAL", "HIGH")
]

if not tp_findings:
    sys.exit(0)

compat = {
    "project": name,
    "findings": [
        {
            "type": f"ReDoS ({t.get('vuln_type', 'unknown')})",
            "severity": t.get("severity", "HIGH"),
            "file": t.get("file", "?"),
            "description": f"CWE-1333: {t.get('reasoning', '')}",
            "poc_scenario": t.get("attack_scenario", ""),
        }
        for t in tp_findings
    ]
}

compat_file = analysis_file.replace(".json", "_compat.json")
with open(compat_file, "w") as f:
    json.dump(compat, f, indent=2, ensure_ascii=False)

os.system(
    f'python3 {base_dir}/scripts/add_finding.py '
    f'--track redos --domain {name} '
    f'--file "{compat_file}" --report "{report_file}"'
)
PYEOF

        log "리포트 저장: $REPORT_FILE"

        # ── git commit & push ──
        log "Phase 4a: 리포트 git commit & push"
        commit_and_push_report "$REPORT_FILE" "$NAME"

        # ── Discord 알림 ──
        log "Phase 4b: Discord 알림 전송"
        python3 "$NOTIFY_DISCORD" \
          --report "$REPORT_FILE" \
          --project "$NAME" \
          --repo-url "$REPO_URL" \
          --analysis "$ANALYSIS_FILE" \
          --branch "$BRANCH" \
          2>/dev/null || log "WARN: Discord 알림 실패"

      else
        log "WARN: 리포트 생성 실패"
      fi
    else
      log "Phase 4: TP HIGH/CRITICAL 없음 — 리포트 스킵"
    fi
  fi

  SCANNED_REPOS=$((SCANNED_REPOS + 1))
  log "=== $NAME 완료 ==="
done

log "Track 4 ReDoS 파이프라인 완료 (${SCANNED_REPOS}개 스캔, ${FAILED_REPOS}개 실패)"
