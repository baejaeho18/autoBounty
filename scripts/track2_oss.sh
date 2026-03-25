#!/usr/bin/env bash
# ============================================================
# Track 2: 오픈소스 코드 감사 자동 파이프라인
# 매일 실행 — Clone/Pull → 변경 감지 → /security-review → Semgrep → 심층분석 → 리포트
# (변경 없는 레포는 자동 스킵)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$(dirname "$SCRIPT_DIR")"
TRACK_DIR="$BASE/data/track2"
TARGETS="$BASE/data/targets_oss.json"
CONFIG="$BASE/config.json"
EXTRACT_JSON="$BASE/scripts/extract_json.py"
DATE=$(date +%Y-%m-%d)

mkdir -p "$TRACK_DIR"/{repos,scans,analysis,reports}

log() { echo "[T2 $(date '+%H:%M:%S')] $1"; }

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

# ─── 타겟 읽기 ───
python3 -c "
import json
with open('$TARGETS') as f:
    targets = json.load(f)
for t in targets:
    print(f\"{t['repo_url']}|{t['name']}|{t.get('language','unknown')}\")
" | while IFS='|' read -r REPO_URL NAME LANG; do

  log "=== $NAME ($LANG) 감사 시작 ==="
  REPO_DIR="$TRACK_DIR/repos/$NAME"

  # ──────────────────────────────────────
  # Phase 1: Clone 또는 Pull — 완전 자동
  # ──────────────────────────────────────
  if [[ -d "$REPO_DIR/.git" ]]; then
    log "Phase 1: git pull (기존 레포)"
    PREV_HASH=$(git -C "$REPO_DIR" rev-parse HEAD)
    git -C "$REPO_DIR" pull --quiet 2>/dev/null || {
      log "WARN: git pull 실패 ($NAME)"
      continue
    }
    NEW_HASH=$(git -C "$REPO_DIR" rev-parse HEAD)

    if [[ "$PREV_HASH" == "$NEW_HASH" ]]; then
      log "변경 없음 — $NAME 스킵"
      continue
    fi

    # 변경된 파일 목록
    git -C "$REPO_DIR" diff --name-only "$PREV_HASH" "$NEW_HASH" > "$TRACK_DIR/scans/${NAME}_changed_${DATE}.txt"
    CHANGED_COUNT=$(wc -l < "$TRACK_DIR/scans/${NAME}_changed_${DATE}.txt")
    log "${CHANGED_COUNT}개 파일 변경 감지"
  else
    log "Phase 1: git clone (신규)"
    if ! git clone --depth 100 "$REPO_URL" "$REPO_DIR" 2>/dev/null; then
      log "ERROR: git clone 실패 ($NAME) — 스킵"
      continue
    fi
  fi

  # ──────────────────────────────────────
  # Phase 2: 자동 스캔 도구들 — 완전 자동
  # ──────────────────────────────────────
  log "Phase 2a: Semgrep 스캔"
  if command -v semgrep &>/dev/null; then
    if semgrep scan --config auto --json \
      -o "$TRACK_DIR/scans/${NAME}_semgrep_${DATE}.json" \
      "$REPO_DIR" 2>/dev/null; then
      SEMGREP_COUNT=$(python3 -c "
import json
try:
    with open('$TRACK_DIR/scans/${NAME}_semgrep_${DATE}.json') as f:
        print(len(json.load(f).get('results', [])))
except: print(0)
" 2>/dev/null || echo "0")
      log "Semgrep: ${SEMGREP_COUNT}건 발견"
    else
      log "WARN: Semgrep 스캔 실패"
    fi
  else
    log "WARN: semgrep 미설치 — 스킵"
  fi

  log "Phase 2b: 의존성 CVE 스캔"
  if [[ -f "$REPO_DIR/requirements.txt" ]] && command -v pip-audit &>/dev/null; then
    pip-audit -r "$REPO_DIR/requirements.txt" --format json \
      -o "$TRACK_DIR/scans/${NAME}_deps_${DATE}.json" 2>/dev/null || \
      log "WARN: pip-audit 실패"
  elif [[ -f "$REPO_DIR/package.json" ]]; then
    (cd "$REPO_DIR" && npm audit --json > "$TRACK_DIR/scans/${NAME}_deps_${DATE}.json" 2>/dev/null) || \
      log "WARN: npm audit 실패"
  fi

  # ──────────────────────────────────────
  # Phase 3: Claude 심층 분석 — 자동 (claude -p)
  # ──────────────────────────────────────
  log "Phase 3: Claude Code 심층 보안 분석"

  # 주요 파일 목록 수집 (인증/인가 관련) — subshell로 cd 격리
  AUTH_FILES=$(grep -rlE "(auth|login|permission|session|token|middleware|decorator|guard)" \
    --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.php" \
    "$REPO_DIR" 2>/dev/null | head -20 | tr '\n' ',' || echo "없음")

  # 라우트/엔드포인트 파일
  ROUTE_FILES=$(find "$REPO_DIR" -name "*.py" -o -name "*.js" -o -name "*.ts" 2>/dev/null | \
    xargs grep -lE "(route|router|endpoint|app\.(get|post|put|delete)|@api)" 2>/dev/null | \
    head -20 | tr '\n' ',' || echo "없음")

  # Semgrep 결과 요약
  SEMGREP_SUMMARY=""
  if [[ -f "$TRACK_DIR/scans/${NAME}_semgrep_${DATE}.json" ]]; then
    SEMGREP_SUMMARY=$(python3 -c "
import json
try:
    with open('$TRACK_DIR/scans/${NAME}_semgrep_${DATE}.json') as f:
        data = json.load(f)
    for r in data.get('results', [])[:15]:
        sev = r.get('extra', {}).get('severity', '?')
        msg = r.get('extra', {}).get('message', '')[:100]
        path = r.get('path', '?')
        line = r.get('start', {}).get('line', '?')
        print(f'- [{sev}] {path}:{line} — {msg}')
except: pass
" 2>/dev/null || echo "Semgrep 결과 없음")
  fi

  ANALYSIS_FILE="$TRACK_DIR/analysis/${NAME}_${DATE}.json"

  claude -p "
당신은 시니어 보안 연구원입니다. 이 $LANG 프로젝트($NAME)를 감사하세요.

## 인증/인가 관련 파일:
$AUTH_FILES

## 라우트/엔드포인트 파일:
$ROUTE_FILES

## Semgrep 스캔 결과:
$SEMGREP_SUMMARY

다음을 분석하세요:
1. 인증 미들웨어 없이 노출된 엔드포인트 (CRITICAL)
2. 수평/수직 권한 상승 가능 지점 (HIGH)
3. SQL 인젝션, 커맨드 인젝션, SSTI 경로 (HIGH)
4. 레이스 컨디션 가능 지점 (MEDIUM)
5. 파일 업로드/다운로드 검증 우회 (MEDIUM)

중요: 일반적인 보안 모범 사례 위반은 제외하고, 실제 exploit 가능한 취약점만 포함하세요.
프레임워크가 기본 제공하는 보호 기능으로 막히는 케이스도 제외하세요.

결과를 아래 JSON으로만 출력:
{
  \"project\": \"$NAME\",
  \"date\": \"$DATE\",
  \"findings\": [
    {
      \"type\": \"취약점 유형\",
      \"severity\": \"CRITICAL/HIGH/MEDIUM/LOW\",
      \"file\": \"파일:라인\",
      \"description\": \"상세 설명\",
      \"poc_scenario\": \"PoC 시나리오\",
      \"fix_suggestion\": \"수정 제안\"
    }
  ]
}
" 2>/dev/null | python3 "$EXTRACT_JSON" > "$ANALYSIS_FILE"

  # JSON 추출 실패 체크
  if ! python3 -c "import json; d=json.load(open('$ANALYSIS_FILE')); assert 'error' not in d" 2>/dev/null; then
    log "WARN: Claude JSON 파싱 실패 — $NAME Phase 3 결과 불완전"
    continue
  fi

  # ──────────────────────────────────────
  # Phase 4: 리포트 초안 — 자동
  # ──────────────────────────────────────
  CRIT_HIGH=$(python3 -c "
import json
try:
    with open('$ANALYSIS_FILE') as f:
        data = json.load(f)
    findings = [f for f in data.get('findings', []) if f.get('severity') in ('CRITICAL', 'HIGH')]
    print(len(findings))
except: print(0)
" 2>/dev/null || echo "0")

  if [[ "$CRIT_HIGH" -gt 0 ]]; then
    log "!! CRITICAL/HIGH $CRIT_HIGH건 — 리포트 초안 생성"

    ANALYSIS=$(cat "$ANALYSIS_FILE")
    REPORT_FILE="$TRACK_DIR/reports/${NAME}_${DATE}_report.md"

    claude -p "
아래 보안 감사 결과를 바탕으로 Responsible Disclosure 리포트를 작성하세요.

$ANALYSIS

형식:
# Security Vulnerability Report: $NAME
## Summary
## Vulnerability Details (각 HIGH/CRITICAL 건에 대해)
### [제목]
- Type: [CWE-XXX]
- Severity: [CVSS 3.1 점수]
- File: [파일:라인]
- Description:
- Steps to Reproduce:
- Impact:
- Suggested Fix:
## Timeline
- Discovered: $DATE
- Vendor notification: [TBD - 수동]
- Public disclosure: 90 days after vendor notification
" > "$REPORT_FILE" 2>/dev/null

    if [[ -s "$REPORT_FILE" ]]; then
      python3 "$BASE/scripts/add_finding.py" \
        --track "oss" \
        --domain "$NAME" \
        --file "$ANALYSIS_FILE" \
        --report "$REPORT_FILE"
      log "리포트 저장: $REPORT_FILE"
    else
      log "WARN: 리포트 생성 실패"
    fi
  else
    log "CRITICAL/HIGH 건 없음 — 리포트 스킵"
  fi

  log "=== $NAME 완료 ==="
done

log "Track 2 파이프라인 완료"
