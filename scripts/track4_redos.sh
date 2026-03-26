#!/usr/bin/env bash
# ============================================================
# Track 4: ReDoS (Regular Expression Denial of Service) 취약점 스캐너
# Google Bug Hunters OSS VRP 대상 레포지토리를 스캔
#
# 2-Pass 파이프라인:
#   Pass 1: 전체 레포 Clone/Pull → 정적 분석 (LLM 불필요)
#   Pass 2: CRITICAL/HIGH 발견 레포만 LLM 정밀 분석 → 리포트 → push → Discord
#           (토큰 소진 시 대기 후 재시도)
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
DISCORD="$BASE/scripts/discord_helper.py"
DATE=$(date +%Y-%m-%d)
BRANCH=$(git -C "$BASE" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")

# LLM 질의 대기열
LLM_QUEUE_FILE="$TRACK_DIR/.llm_queue_${DATE}.txt"
LLM_DONE_FILE="$TRACK_DIR/.llm_done_${DATE}.txt"
DISCORD_MSG_FILE="$TRACK_DIR/.discord_msg_ids_${DATE}.txt"

# 토큰 리셋 대기 설정 (분)
TOKEN_RESET_WAIT_MIN=${TOKEN_RESET_WAIT_MIN:-60}
MAX_LLM_RETRIES=${MAX_LLM_RETRIES:-5}

mkdir -p "$TRACK_DIR"/{repos,scans,analysis,reports}
touch "$LLM_QUEUE_FILE" "$LLM_DONE_FILE" "$DISCORD_MSG_FILE"
PIPELINE_START_TS=$(date +%s)

log() { echo "[T4 $(date '+%H:%M:%S')] $1"; }

# Discord 헬퍼 (실패해도 파이프라인 중단 안 함)
discord() { python3 "$DISCORD" "$@" 2>/dev/null || true; }

# Discord 메시지 ID 저장/조회
save_msg_id() { echo "$1|$2" >> "$DISCORD_MSG_FILE"; }
get_msg_id() { grep "^$1|" "$DISCORD_MSG_FILE" 2>/dev/null | tail -1 | cut -d'|' -f2; }

# ──────────────────────────────────────
# 헬퍼: LLM 호출 + 토큰 소진 감지
# ──────────────────────────────────────
call_claude() {
  local prompt="$1" allowed_tools="$2" output_file="$3"
  local tmp_out tmp_err exit_code
  tmp_out=$(mktemp); tmp_err=$(mktemp)

  exit_code=0
  claude -p "$prompt" --allowedTools "$allowed_tools" \
    >"$tmp_out" 2>"$tmp_err" \
    || exit_code=$?

  local err_content
  err_content=$(cat "$tmp_err" 2>/dev/null || true)

  if [[ $exit_code -ne 0 ]] || \
     echo "$err_content" | grep -qiE "rate.?limit|token.?limit|quota|exceeded|capacity|overloaded|529|429|too many"; then
    rm -f "$tmp_out" "$tmp_err"
    return 2
  fi

  if [[ ! -s "$tmp_out" ]]; then
    rm -f "$tmp_out" "$tmp_err"
    return 1
  fi

  cat "$tmp_out" | python3 "$EXTRACT_JSON" > "$output_file" 2>/dev/null
  local json_exit=$?
  rm -f "$tmp_out" "$tmp_err"

  if [[ $json_exit -ne 0 ]] || grep -q '"error"' "$output_file" 2>/dev/null; then
    return 1
  fi
  return 0
}

# ──────────────────────────────────────
# 헬퍼: 리포트 git commit + push
# ──────────────────────────────────────
commit_and_push_report() {
  local report_file="$1" project_name="$2"
  local rel_path
  rel_path=$(python3 -c "import os; print(os.path.relpath('$report_file', '$BASE'))")
  git -C "$BASE" add "$rel_path"
  git -C "$BASE" commit -m "Add ReDoS report: ${project_name} (${DATE})" 2>/dev/null || {
    log "WARN: git commit 실패 (변경 없음?)"
    return 1
  }
  local attempt=0 wait_sec=2
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
# 헬퍼: 단일 프로젝트 LLM 분석 + 리포트
# ──────────────────────────────────────
run_llm_analysis() {
  local REPO_URL="$1" NAME="$2" LANG="$3" TIER="$4"
  local REPO_DIR="$TRACK_DIR/repos/$NAME"
  local SCAN_FILE="$TRACK_DIR/scans/${NAME}_redos_${DATE}.json"
  local ANALYSIS_FILE="$TRACK_DIR/analysis/${NAME}_redos_${DATE}.json"
  local ALLOWED_TOOLS="Read,Grep,Glob,Bash(ls:*),Bash(head:*),Bash(wc:*),Bash(find:*),Bash(python3:*)"

  if grep -qF "$NAME" "$LLM_DONE_FILE" 2>/dev/null; then
    log "[$NAME] 이미 LLM 분석 완료 — 스킵"
    return 0
  fi

  if [[ ! -f "$SCAN_FILE" ]]; then
    log "[$NAME] 스캔 결과 없음 — 스킵"
    return 0
  fi

  local CRIT_HIGH
  CRIT_HIGH=$(python3 -c "
import json
try:
    with open('$SCAN_FILE') as f:
        data = json.load(f)
    s = data.get('stats', {})
    print(s.get('critical', 0) + s.get('high', 0))
except: print(0)
" 2>/dev/null || echo "0")

  if [[ "$CRIT_HIGH" -eq 0 ]]; then
    log "[$NAME] CRITICAL/HIGH 없음 — LLM 분석 스킵"
    echo "$NAME" >> "$LLM_DONE_FILE"
    return 0
  fi

  log "[$NAME] LLM 정밀 분석 시작 (${CRIT_HIGH}건 TP/FP 판별)"

  local SCAN_SUMMARY
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

  local LLM_PROMPT="
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
"

  call_claude "$LLM_PROMPT" "$ALLOWED_TOOLS" "$ANALYSIS_FILE"
  local llm_exit=$?

  if [[ $llm_exit -eq 2 ]]; then
    log "[$NAME] 토큰/Rate limit 도달 — 대기열에 추가"
    return 2
  fi

  if [[ $llm_exit -ne 0 ]]; then
    log "[$NAME] WARN: LLM 분석 실패 (일반 에러)"
    echo "$NAME" >> "$LLM_DONE_FILE"
    return 1
  fi

  # LLM 결과 파싱
  local LLM_STATS
  LLM_STATS=$(python3 - "$ANALYSIS_FILE" <<'PYEOF'
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    triage = data.get("redos_triage", [])
    tp = [t for t in triage if t.get("verdict") == "TP"]
    fp = [t for t in triage if t.get("verdict") == "FP"]
    tp_crit = len([t for t in tp if t.get("severity") == "CRITICAL"])
    tp_high = len([t for t in tp if t.get("severity") == "HIGH"])
    tp_med  = len([t for t in tp if t.get("severity") == "MEDIUM"])
    tp_low  = len([t for t in tp if t.get("severity") == "LOW"])
    # TP details JSON
    tp_details = json.dumps([{
        "severity": t.get("severity","?"),
        "vuln_type": t.get("vuln_type","?"),
        "file": t.get("file","?"),
        "pattern": t.get("pattern","?"),
        "reasoning": t.get("reasoning","")
    } for t in tp], ensure_ascii=False)
    print(f"{len(tp)}|{len(fp)}|{tp_crit}|{tp_high}|{tp_med}|{tp_low}|{tp_details}")
except:
    print("0|0|0|0|0|0|[]")
PYEOF
  )

  IFS='|' read -r TP_COUNT FP_COUNT TP_CRIT TP_HIGH TP_MED TP_LOW TP_DETAILS <<< "$LLM_STATS"
  log "[$NAME] LLM 분석 완료: TP ${TP_COUNT}건 / FP ${FP_COUNT}건"

  # Discord: LLM 결과 → 정적 분석 메시지 편집
  local STATIC_MSG_ID
  STATIC_MSG_ID=$(get_msg_id "$NAME")
  if [[ -n "$STATIC_MSG_ID" ]]; then
    discord llm-result \
      --name "$NAME" \
      --edit-msg-id "$STATIC_MSG_ID" \
      --tp "$TP_COUNT" --fp "$FP_COUNT" \
      --critical "$TP_CRIT" --high "$TP_HIGH" --medium "$TP_MED" --low "$TP_LOW" \
      --tp-details "$TP_DETAILS"
  fi

  # ── 리포트 생성: 모든 TP에 대해 (severity 무관) ──
  if [[ "$TP_COUNT" -gt 0 ]]; then
    log "[$NAME] 리포트 생성 (TP: ${TP_COUNT}건)"

    local ANALYSIS_CONTENT REPORT_FILE
    ANALYSIS_CONTENT=$(cat "$ANALYSIS_FILE")
    REPORT_FILE="$TRACK_DIR/reports/${NAME}_redos_${DATE}_report.md"

    local REPORT_PROMPT="
아래 ReDoS 취약점 분석 결과를 바탕으로 Responsible Disclosure 리포트를 작성하세요.
TP(True Positive)로 판별된 모든 건을 포함합니다.

$ANALYSIS_CONTENT

형식:
# ReDoS Vulnerability Report: $NAME
## Summary
- 발견된 ReDoS 취약점 수, 심각도 분포
## Methodology
- Static regex pattern analysis (nested quantifiers, overlapping alternations)
- LLM-assisted triage (TP/FP classification with code context analysis)
- Empirical backtracking verification
## Vulnerability Details (각 TP 건에 대해)
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
"

    exit_code=0
    claude -p "$REPORT_PROMPT" > "$REPORT_FILE" 2>/dev/null || exit_code=$?
    if [[ $exit_code -ne 0 ]] || [[ ! -s "$REPORT_FILE" ]]; then
      log "[$NAME] WARN: 리포트 생성 실패 (토큰 소진 가능)"
      return 2
    fi

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
    if t.get("verdict") == "TP"
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

    log "[$NAME] 리포트 저장: $REPORT_FILE"

    # git commit & push
    commit_and_push_report "$REPORT_FILE" "$NAME"

    # Discord: 리포트 내용 알림
    discord report --name "$NAME" --report-file "$REPORT_FILE" --branch "$BRANCH"

  else
    log "[$NAME] TP 없음 — 리포트 스킵"
  fi

  echo "$NAME" >> "$LLM_DONE_FILE"
  return 0
}

# ══════════════════════════════════════
# PASS 1: 전체 레포 Clone + 정적 분석
# ══════════════════════════════════════
log "Phase 0: Google Bug Hunters OSS VRP 레포 목록 가져오기"
python3 "$FETCH_REPOS" || {
  log "WARN: 레포 목록 갱신 실패 — 기존 목록 사용"
}

TARGET_COUNT=$(python3 -c "
import json
with open('$TARGETS') as f:
    print(len(json.load(f)))
" 2>/dev/null || echo "0")

if [[ "$TARGET_COUNT" == "0" ]]; then
  log "등록된 OSS 타겟 없음 — 종료"
  exit 0
fi

log "══════════════════════════════════════"
log "PASS 1: 전체 ${TARGET_COUNT}개 레포 Clone + 정적 ReDoS 분석"
log "══════════════════════════════════════"

SCANNED_REPOS=0
REPO_INDEX=0
FAILED_REPOS=0
NEED_LLM=0

python3 -c "
import json
with open('$TARGETS') as f:
    targets = json.load(f)
for t in targets:
    print(f\"{t['repo_url']}|{t['name']}|{t.get('language','unknown')}|{t.get('tier','UNKNOWN')}\")
" | while IFS='|' read -r REPO_URL NAME LANG TIER; do

  REPO_INDEX=$((REPO_INDEX + 1))
  log "--- [$TIER] $NAME ($LANG) [$REPO_INDEX/$TARGET_COUNT] ---"

  # 상태 파일 업데이트
  cat > "$BASE/.orchestrator.status" << STEOF
상태: Pass 1 정적 분석
진행: ${REPO_INDEX}/${TARGET_COUNT}
현재: $NAME ($LANG)
티어: $TIER
시작: $(date '+%Y-%m-%d %H:%M:%S')
STEOF

  # Discord: 레포 스캐닝 시작 알림
  discord repo-start --name "$NAME" --tier "$TIER" --lang "$LANG" \
    --index "$REPO_INDEX" --total "$TARGET_COUNT"

  REPO_DIR="$TRACK_DIR/repos/$NAME"

  # Clone 또는 Pull
  if [[ -d "$REPO_DIR/.git" ]]; then
    git -C "$REPO_DIR" pull --quiet 2>/dev/null || {
      log "WARN: git pull 실패 ($NAME) — 기존 코드로 계속"
    }
  else
    if ! git clone --depth 1 "$REPO_URL" "$REPO_DIR" 2>/dev/null; then
      log "ERROR: git clone 실패 ($NAME) — 스킵"
      continue
    fi
  fi

  # 정적 ReDoS 스캔
  SCAN_FILE="$TRACK_DIR/scans/${NAME}_redos_${DATE}.json"
  if python3 "$REDOS_SCANNER" "$REPO_DIR" \
      --name "$NAME" \
      --output "$SCAN_FILE" \
      --min-severity LOW 2>/dev/null; then

    # 스캔 결과 파싱
    SCAN_STATS=$(python3 - "$SCAN_FILE" <<'PYEOF'
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    s = data.get("stats", {})
    total = s.get("total_findings", 0)
    crit = s.get("critical", 0)
    high = s.get("high", 0)
    med = s.get("medium", 0)
    low = s.get("low", 0)
    # findings details JSON for discord
    findings = data.get("findings", [])
    details = json.dumps([{
        "severity": f.get("severity","?"),
        "vuln_type": f.get("vuln_type","?"),
        "file": f.get("file","?"),
        "line": f.get("line","?")
    } for f in findings[:10]], ensure_ascii=False)
    print(f"{total}|{crit}|{high}|{med}|{low}|{details}")
except:
    print("0|0|0|0|0|[]")
PYEOF
    )

    IFS='|' read -r FINDING_COUNT CRIT HIGH MED LOW DETAILS <<< "$SCAN_STATS"
    CRIT_HIGH=$((CRIT + HIGH))
    log "정적 스캔: ${FINDING_COUNT}건 (C: ${CRIT} H: ${HIGH} M: ${MED} L: ${LOW})"

    # Discord: 정적 분석 검출 알림 (검출된 경우만)
    if [[ "$FINDING_COUNT" -gt 0 ]]; then
      STATIC_MSG_ID=$(discord static-found \
        --name "$NAME" \
        --findings "$FINDING_COUNT" \
        --critical "$CRIT" --high "$HIGH" --medium "$MED" --low "$LOW" \
        --details "$DETAILS")
      # 메시지 ID 저장 (나중에 LLM 결과로 편집)
      if [[ -n "$STATIC_MSG_ID" ]]; then
        save_msg_id "$NAME" "$STATIC_MSG_ID"
      fi
    fi

    # LLM 분석이 필요한 프로젝트를 큐에 추가
    if [[ "$CRIT_HIGH" -gt 0 ]]; then
      if ! grep -qF "$NAME" "$LLM_DONE_FILE" 2>/dev/null; then
        if ! grep -qF "$NAME" "$LLM_QUEUE_FILE" 2>/dev/null; then
          echo "${REPO_URL}|${NAME}|${LANG}|${TIER}" >> "$LLM_QUEUE_FILE"
        fi
      fi
    fi
  else
    log "WARN: ReDoS 스캐너 실패 ($NAME)"
    FINDING_COUNT=0
    CRIT_HIGH=0
  fi

  # Discord: 레포 완료 알림 (진행률)
  discord repo-done --name "$NAME" \
    --index "$REPO_INDEX" --total "$TARGET_COUNT" \
    --static "${FINDING_COUNT:-0}" --tp 0
done

# 큐 카운트
LLM_QUEUE_COUNT=$(wc -l < "$LLM_QUEUE_FILE" 2>/dev/null | tr -d ' ')
log "══════════════════════════════════════"
log "PASS 1 완료: 정적 분석 종료"
log "LLM 분석 대기열: ${LLM_QUEUE_COUNT}개 프로젝트"
log "══════════════════════════════════════"

# ══════════════════════════════════════
# PASS 2: LLM 정밀 분석 (토큰 소진 시 대기 후 재시도)
# ══════════════════════════════════════
if [[ "$LLM_QUEUE_COUNT" -eq 0 ]]; then
  log "LLM 분석 대상 없음 — 파이프라인 완료"
else

log "══════════════════════════════════════"
log "PASS 2: LLM 정밀 분석 시작 (${LLM_QUEUE_COUNT}개)"
log "══════════════════════════════════════"

RETRY_ROUND=0

while [[ $RETRY_ROUND -lt $MAX_LLM_RETRIES ]]; do
  TOKEN_EXHAUSTED=false
  REMAINING=0

  while IFS='|' read -r REPO_URL NAME LANG TIER; do
    if grep -qF "$NAME" "$LLM_DONE_FILE" 2>/dev/null; then
      continue
    fi
    REMAINING=$((REMAINING + 1))

    cat > "$BASE/.orchestrator.status" << STEOF
상태: Pass 2 LLM 분석
현재: $NAME ($LANG)
대기열: ${LLM_QUEUE_COUNT}개 중 진행
라운드: $((RETRY_ROUND + 1))/${MAX_LLM_RETRIES}
시간: $(date '+%Y-%m-%d %H:%M:%S')
STEOF
    run_llm_analysis "$REPO_URL" "$NAME" "$LANG" "$TIER"
    local_exit=$?

    if [[ $local_exit -eq 2 ]]; then
      TOKEN_EXHAUSTED=true
      log "토큰 소진 감지 — 나머지 프로젝트 대기열 유지"
      break
    fi
  done < "$LLM_QUEUE_FILE"

  DONE_COUNT=$(wc -l < "$LLM_DONE_FILE" 2>/dev/null | tr -d ' ')
  PENDING=$(python3 -c "
done_set = set()
try:
    with open('$LLM_DONE_FILE') as f:
        done_set = set(l.strip() for l in f)
except: pass
count = 0
try:
    with open('$LLM_QUEUE_FILE') as f:
        for line in f:
            name = line.strip().split('|')[1]
            if name not in done_set:
                count += 1
except: pass
print(count)
" 2>/dev/null || echo "0")

  if [[ "$PENDING" -eq 0 ]]; then
    log "LLM 분석 전체 완료 (${DONE_COUNT}개 처리)"
    break
  fi

  if [[ "$TOKEN_EXHAUSTED" == "true" ]]; then
    RETRY_ROUND=$((RETRY_ROUND + 1))
    log "══════════════════════════════════════"
    log "토큰 리셋 대기 (${TOKEN_RESET_WAIT_MIN}분)..."
    log "남은 프로젝트: ${PENDING}개 | 재시도: ${RETRY_ROUND}/${MAX_LLM_RETRIES}"
    log "══════════════════════════════════════"
    sleep $((TOKEN_RESET_WAIT_MIN * 60))
    log "토큰 리셋 대기 완료 — 재시도 시작"
  else
    RETRY_ROUND=$((RETRY_ROUND + 1))
    if [[ $RETRY_ROUND -lt $MAX_LLM_RETRIES ]]; then
      log "일반 에러로 실패한 건 재시도 (${RETRY_ROUND}/${MAX_LLM_RETRIES})"
    fi
  fi
done

fi  # LLM_QUEUE_COUNT > 0

# ══════════════════════════════════════
# 완료 집계 + Discord 파이프라인 완료 알림
# ══════════════════════════════════════
FINAL_DONE=$(wc -l < "$LLM_DONE_FILE" 2>/dev/null | tr -d ' ')
FINAL_PENDING=$(python3 -c "
done_set = set()
try:
    with open('$LLM_DONE_FILE') as f:
        done_set = set(l.strip() for l in f)
except: pass
count = 0
try:
    with open('$LLM_QUEUE_FILE') as f:
        for line in f:
            name = line.strip().split('|')[1]
            if name not in done_set:
                count += 1
except: pass
print(count)
" 2>/dev/null || echo "0")

if [[ "$FINAL_PENDING" -gt 0 ]]; then
  log "WARN: LLM 분석 미완료 ${FINAL_PENDING}건 (다음 실행에서 재시도)"
fi

# 스캔 결과 집계
TOTAL_FINDINGS=$(python3 -c "
import json, os, glob
total = crit = high = med = low = 0
for f in glob.glob('$TRACK_DIR/scans/*_redos_${DATE}.json'):
    try:
        with open(f) as fh:
            s = json.load(fh).get('stats', {})
        total += s.get('total_findings', 0)
        crit += s.get('critical', 0)
        high += s.get('high', 0)
        med += s.get('medium', 0)
        low += s.get('low', 0)
    except: pass
print(f'{total}|{crit}|{high}|{med}|{low}')
" 2>/dev/null || echo "0|0|0|0|0")

IFS='|' read -r STAT_TOTAL STAT_CRIT STAT_HIGH STAT_MED STAT_LOW <<< "$TOTAL_FINDINGS"

TP_TOTAL=$(python3 -c "
import json, os, glob
tp = 0
for f in glob.glob('$TRACK_DIR/analysis/*_redos_${DATE}.json'):
    try:
        with open(f) as fh:
            data = json.load(fh)
        tp += len([t for t in data.get('redos_triage', []) if t.get('verdict') == 'TP'])
    except: pass
print(tp)
" 2>/dev/null || echo "0")

REPORT_COUNT=$(ls -1 "$TRACK_DIR/reports/"*_redos_${DATE}_report.md 2>/dev/null | wc -l | tr -d ' ')

# Discord: 파이프라인 전체 완료 알림
discord pipeline-done \
  --date "$DATE" \
  --total-repos "$TARGET_COUNT" \
  --static-total "$STAT_TOTAL" \
  --static-crit "$STAT_CRIT" \
  --static-high "$STAT_HIGH" \
  --static-med "$STAT_MED" \
  --static-low "$STAT_LOW" \
  --llm-done "$FINAL_DONE" \
  --llm-pending "$FINAL_PENDING" \
  --tp-total "$TP_TOTAL" \
  --report-count "$REPORT_COUNT"

log "═══════════════════════════════════════════"
log "Track 4 ReDoS 파이프라인 전체 완료"
log "═══════════════════════════════════════════"
