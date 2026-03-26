#!/usr/bin/env bash
# Phase 2만 재개: 남은 LLM 분석 처리
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$(dirname "$SCRIPT_DIR")"
TRACK_DIR="$BASE/data/track4"
DATE=$(date +%Y-%m-%d)
CONFIG="$BASE/config.json"
EXTRACT_JSON="$BASE/scripts/extract_json.py"
NOTIFY_DISCORD="$BASE/scripts/notify_discord.py"
BRANCH=$(git -C "$BASE" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
LLM_QUEUE_FILE="$TRACK_DIR/.llm_queue_${DATE}.txt"
LLM_DONE_FILE="$TRACK_DIR/.llm_done_${DATE}.txt"
TOKEN_RESET_WAIT_MIN=${TOKEN_RESET_WAIT_MIN:-60}
MAX_LLM_RETRIES=${MAX_LLM_RETRIES:-5}
LOGFILE="$BASE/logs/${DATE}-redos-phase2.log"

log() { echo "[T4 $(date '+%H:%M:%S')] $1" | tee -a "$LOGFILE"; }

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
    log "claude 실패 (exit=$exit_code): $(head -1 "$tmp_err" 2>/dev/null || echo 'unknown')"
    rm -f "$tmp_out" "$tmp_err"
    return 2
  fi
  if [[ ! -s "$tmp_out" ]]; then
    rm -f "$tmp_out" "$tmp_err"
    return 1
  fi
  python3 "$EXTRACT_JSON" < "$tmp_out" > "$output_file" 2>/dev/null
  local json_exit=$?
  rm -f "$tmp_out" "$tmp_err"
  if [[ $json_exit -ne 0 ]] || grep -q '"error"' "$output_file" 2>/dev/null; then
    return 1
  fi
  return 0
}

commit_and_push_report() {
  local report_file="$1" project_name="$2"
  local rel_path
  rel_path=$(python3 -c "import os; print(os.path.relpath('$report_file', '$BASE'))")
  git -C "$BASE" add "$rel_path"
  git -C "$BASE" commit -m "Add ReDoS report: ${project_name} (${DATE})" 2>/dev/null || return 1
  local attempt=0 wait_sec=2
  while [[ $attempt -lt 4 ]]; do
    if git -C "$BASE" push -u origin "$BRANCH" 2>/dev/null; then
      log "git push 완료: $rel_path"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep $wait_sec
    wait_sec=$((wait_sec * 2))
  done
  log "ERROR: git push 4회 실패"
  return 1
}

build_scan_summary() {
  local scan_file="$1"
  python3 - "$scan_file" << 'PYEOF'
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
    print("- [{}] {} \u2192 {}:{}".format(f["severity"], f["vuln_type"], f["file"], f["line"]))
    print("  Pattern: {}".format(f["pattern"][:100]))
    print("  Evidence: {}".format(f["evidence"][:80]))
    print("  Description: {}".format(f["description"]))
    print()
PYEOF
}

count_json_field() {
  python3 - "$@" << 'PYEOF'
import json, sys
filepath = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else "tp"
try:
    with open(filepath) as f:
        data = json.load(f)
    triage = data.get("redos_triage", [])
    if mode == "tp":
        print(len([t for t in triage if t.get("verdict") == "TP"]))
    elif mode == "tp_high":
        print(len([t for t in triage
                    if t.get("verdict") == "TP"
                    and t.get("severity") in ("CRITICAL", "HIGH")
                    and t.get("confidence") in ("HIGH", "MEDIUM")]))
    elif mode == "crit_high":
        s = data.get("stats", {})
        print(s.get("critical", 0) + s.get("high", 0))
    else:
        print(0)
except:
    print(0)
PYEOF
}

run_llm_analysis() {
  local REPO_URL="$1" NAME="$2" LANG="$3" TIER="$4"
  local REPO_DIR="$TRACK_DIR/repos/$NAME"
  local SCAN_FILE="$TRACK_DIR/scans/${NAME}_redos_${DATE}.json"
  local ANALYSIS_FILE="$TRACK_DIR/analysis/${NAME}_redos_${DATE}.json"
  local ALLOWED_TOOLS="Read,Grep,Glob,Bash(ls:*),Bash(head:*),Bash(wc:*),Bash(find:*),Bash(python3:*)"

  if grep -qF "$NAME" "$LLM_DONE_FILE" 2>/dev/null; then return 0; fi
  if [[ ! -f "$SCAN_FILE" ]]; then return 0; fi

  local CRIT_HIGH
  CRIT_HIGH=$(count_json_field "$SCAN_FILE" "crit_high")
  if [[ "$CRIT_HIGH" -eq 0 ]]; then echo "$NAME" >> "$LLM_DONE_FILE"; return 0; fi

  log "[$NAME] LLM 정밀 분석 시작 (${CRIT_HIGH}건 TP/FP 판별)"

  local SCAN_SUMMARY
  SCAN_SUMMARY=$(build_scan_summary "$SCAN_FILE")

  local LLM_PROMPT
  LLM_PROMPT=$(cat << PROMPT_EOF
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
  "project": "$NAME",
  "date": "$DATE",
  "redos_triage": [
    {
      "file": "파일:라인",
      "pattern": "정규식 패턴",
      "verdict": "TP 또는 FP",
      "confidence": "HIGH/MEDIUM/LOW",
      "severity": "CRITICAL/HIGH/MEDIUM/LOW",
      "vuln_type": "nested_quantifier/overlapping_alternation/etc",
      "reasoning": "판별 근거 (어떤 파일의 어떤 코드를 확인했는지 포함)",
      "attack_input": "TP일 때: ReDoS를 유발하는 입력 예시",
      "attack_scenario": "TP일 때: 구체적 공격 시나리오",
      "cwe": "CWE-1333"
    }
  ]
}
PROMPT_EOF
  )

  call_claude "$LLM_PROMPT" "$ALLOWED_TOOLS" "$ANALYSIS_FILE"
  local llm_exit=$?
  if [[ $llm_exit -eq 2 ]]; then log "[$NAME] 토큰/Rate limit — 대기열 유지"; return 2; fi
  if [[ $llm_exit -ne 0 ]]; then log "[$NAME] WARN: LLM 분석 실패"; echo "$NAME" >> "$LLM_DONE_FILE"; return 1; fi

  local TP_COUNT
  TP_COUNT=$(count_json_field "$ANALYSIS_FILE" "tp")
  log "[$NAME] LLM 분석 완료: TP ${TP_COUNT}건"

  local TP_HIGH_COUNT
  TP_HIGH_COUNT=$(count_json_field "$ANALYSIS_FILE" "tp_high")

  if [[ "$TP_HIGH_COUNT" -gt 0 ]]; then
    log "[$NAME] 리포트 생성 (TP CRITICAL/HIGH: ${TP_HIGH_COUNT}건)"

    local ANALYSIS_CONTENT REPORT_FILE
    ANALYSIS_CONTENT=$(cat "$ANALYSIS_FILE")
    REPORT_FILE="$TRACK_DIR/reports/${NAME}_redos_${DATE}_report.md"

    local REPORT_PROMPT
    REPORT_PROMPT=$(cat << RPROMPT_EOF
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
- **Vulnerable Pattern**: 정규식
- **Description**: 취약점 상세 설명
- **Attack Input**: ReDoS를 유발하는 구체적 입력
- **Steps to Reproduce**: 구체적 재현 단계
- **Impact**: CPU exhaustion, denial of service
- **Suggested Fix**: 수정 제안 (안전한 정규식 또는 RE2 사용 등)
## Timeline
- Discovered: $DATE
- Vendor notification: [TBD]
RPROMPT_EOF
    )

    exit_code=0
    claude -p "$REPORT_PROMPT" > "$REPORT_FILE" 2>/dev/null || exit_code=$?
    if [[ $exit_code -ne 0 ]] || [[ ! -s "$REPORT_FILE" ]]; then
      log "[$NAME] WARN: 리포트 생성 실패"
      return 2
    fi

    log "[$NAME] 리포트 저장: $REPORT_FILE"
    commit_and_push_report "$REPORT_FILE" "$NAME"

    log "[$NAME] Discord 알림 전송"
    python3 "$NOTIFY_DISCORD" \
      --report "$REPORT_FILE" \
      --project "$NAME" \
      --repo-url "$REPO_URL" \
      --analysis "$ANALYSIS_FILE" \
      --branch "$BRANCH" \
      2>/dev/null || log "[$NAME] WARN: Discord 알림 실패"
  else
    log "[$NAME] TP HIGH/CRITICAL 없음 — 리포트 스킵"
  fi

  echo "$NAME" >> "$LLM_DONE_FILE"
  return 0
}

# ── Main: Phase 2 실행 ──
LLM_QUEUE_COUNT=$(wc -l < "$LLM_QUEUE_FILE" 2>/dev/null | tr -d ' ')
log "══════════════════════════════════════"
log "PASS 2 재개: LLM 정밀 분석 (미처리 건)"
log "══════════════════════════════════════"

RETRY_ROUND=0
while [[ $RETRY_ROUND -lt $MAX_LLM_RETRIES ]]; do
  TOKEN_EXHAUSTED=false
  while IFS='|' read -r REPO_URL NAME LANG TIER; do
    if grep -qF "$NAME" "$LLM_DONE_FILE" 2>/dev/null; then continue; fi
    run_llm_analysis "$REPO_URL" "$NAME" "$LANG" "$TIER"
    local_exit=$?
    if [[ $local_exit -eq 2 ]]; then
      TOKEN_EXHAUSTED=true
      log "토큰 소진 감지 — 나머지 대기열 유지"
      break
    fi
  done < "$LLM_QUEUE_FILE"

  PENDING=$(python3 - "$LLM_DONE_FILE" "$LLM_QUEUE_FILE" << 'PYEOF'
import sys
done_f, queue_f = sys.argv[1], sys.argv[2]
done_set = set()
try:
    with open(done_f) as f:
        done_set = set(l.strip() for l in f)
except: pass
count = 0
try:
    with open(queue_f) as f:
        for line in f:
            name = line.strip().split('|')[1]
            if name not in done_set:
                count += 1
except: pass
print(count)
PYEOF
  )

  if [[ "$PENDING" -eq 0 ]]; then
    log "LLM 분석 전체 완료"
    break
  fi
  if [[ "$TOKEN_EXHAUSTED" == "true" ]]; then
    RETRY_ROUND=$((RETRY_ROUND + 1))
    log "토큰 리셋 대기 (${TOKEN_RESET_WAIT_MIN}분)... 남은: ${PENDING}개 | 재시도: ${RETRY_ROUND}/${MAX_LLM_RETRIES}"
    sleep $((TOKEN_RESET_WAIT_MIN * 60))
  else
    RETRY_ROUND=$((RETRY_ROUND + 1))
  fi
done

# ── 완료 요약 ──
DONE_COUNT=$(wc -l < "$LLM_DONE_FILE" 2>/dev/null | tr -d ' ')
log "══════════════════════════════════════"
log "PASS 2 재개 완료: ${DONE_COUNT}개 처리"
log "══════════════════════════════════════"
