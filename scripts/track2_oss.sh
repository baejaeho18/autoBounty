#!/usr/bin/env bash
# ============================================================
# Track 2: 오픈소스 코드 감사 자동 파이프라인
# 월/목 실행 — Clone/Pull → /security-review → Semgrep → 심층분석 → 리포트
# ============================================================
set -euo pipefail

BASE="$HOME/bounty-autopilot"
TRACK_DIR="$BASE/data/track2"
TARGETS="$BASE/data/targets_oss.json"
DATE=$(date +%Y-%m-%d)

mkdir -p "$TRACK_DIR"/{repos,scans,analysis,reports}

log() { echo "[T2 $(date '+%H:%M:%S')] $1"; }

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
    cd "$REPO_DIR"
    PREV_HASH=$(git rev-parse HEAD)
    git pull --quiet 2>/dev/null || true
    NEW_HASH=$(git rev-parse HEAD)

    if [[ "$PREV_HASH" == "$NEW_HASH" ]]; then
      log "변경 없음 — 스킵"
      continue
    fi

    # 변경된 파일 목록
    git diff --name-only "$PREV_HASH" "$NEW_HASH" > "$TRACK_DIR/scans/${NAME}_changed_${DATE}.txt"
    log "$(wc -l < "$TRACK_DIR/scans/${NAME}_changed_${DATE}.txt")개 파일 변경 감지"
  else
    log "Phase 1: git clone (신규)"
    git clone --depth 100 "$REPO_URL" "$REPO_DIR" 2>/dev/null || true
    cd "$REPO_DIR"
  fi

  # ──────────────────────────────────────
  # Phase 2: 자동 스캔 도구들 — 완전 자동
  # ──────────────────────────────────────
  log "Phase 2a: Semgrep 스캔"
  semgrep scan --config auto --json \
    -o "$TRACK_DIR/scans/${NAME}_semgrep_${DATE}.json" \
    "$REPO_DIR" 2>/dev/null || true

  SEMGREP_COUNT=$(python3 -c "
import json
try:
    with open('$TRACK_DIR/scans/${NAME}_semgrep_${DATE}.json') as f:
        print(len(json.load(f).get('results', [])))
except: print(0)
" 2>/dev/null || echo "0")
  log "Semgrep: ${SEMGREP_COUNT}건 발견"

  log "Phase 2b: 의존성 CVE 스캔"
  if [[ -f "requirements.txt" ]]; then
    pip-audit -r requirements.txt --format json \
      -o "$TRACK_DIR/scans/${NAME}_deps_${DATE}.json" 2>/dev/null || true
  elif [[ -f "package.json" ]]; then
    npm audit --json > "$TRACK_DIR/scans/${NAME}_deps_${DATE}.json" 2>/dev/null || true
  fi

  # ──────────────────────────────────────
  # Phase 3: Claude 심층 분석 — 자동 (claude -p)
  # ──────────────────────────────────────
  log "Phase 3: Claude Code 심층 보안 분석"

  # 주요 파일 목록 수집 (인증/인가 관련)
  AUTH_FILES=$(grep -rlE "(auth|login|permission|session|token|middleware|decorator|guard)" \
    --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" --include="*.php" \
    "$REPO_DIR" 2>/dev/null | head -20 | tr '\n' ',' || echo "없음")

  # 라우트/엔드포인트 파일
  ROUTE_FILES=$(find "$REPO_DIR" -name "*.py" -o -name "*.js" -o -name "*.ts" | \
    xargs grep -lE "(route|router|endpoint|app\.(get|post|put|delete)|@api)" 2>/dev/null | \
    head -20 | tr '\n' ',' || echo "없음")

  cd "$REPO_DIR"

  claude -p "
당신은 시니어 보안 연구원입니다. 이 $LANG 프로젝트($NAME)를 감사하세요.

## 인증/인가 관련 파일:
$AUTH_FILES

## 라우트/엔드포인트 파일:
$ROUTE_FILES

다음을 분석하세요:
1. 인증 미들웨어 없이 노출된 엔드포인트 (CRITICAL)
2. 수평/수직 권한 상승 가능 지점 (HIGH)
3. SQL 인젝션, 커맨드 인젝션, SSTI 경로 (HIGH)
4. 레이스 컨디션 가능 지점 (MEDIUM)
5. 파일 업로드/다운로드 검증 우회 (MEDIUM)

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
" > "$TRACK_DIR/analysis/${NAME}_${DATE}.json" 2>/dev/null || true

  # ──────────────────────────────────────
  # Phase 4: 리포트 초안 — 자동
  # ──────────────────────────────────────
  CRIT_HIGH=$(python3 -c "
import json
try:
    with open('$TRACK_DIR/analysis/${NAME}_${DATE}.json') as f:
        data = json.load(f)
    findings = [f for f in data.get('findings', []) if f.get('severity') in ('CRITICAL', 'HIGH')]
    print(len(findings))
except: print(0)
" 2>/dev/null || echo "0")

  if [[ "$CRIT_HIGH" -gt 0 ]]; then
    log "!! CRITICAL/HIGH $CRIT_HIGH건 — 리포트 초안 생성"

    ANALYSIS=$(cat "$TRACK_DIR/analysis/${NAME}_${DATE}.json")

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
" > "$TRACK_DIR/reports/${NAME}_${DATE}_report.md" 2>/dev/null || true

    python3 "$BASE/scripts/add_finding.py" \
      --track "oss" \
      --domain "$NAME" \
      --file "$TRACK_DIR/analysis/${NAME}_${DATE}.json" \
      --report "$TRACK_DIR/reports/${NAME}_${DATE}_report.md"
  fi

  log "=== $NAME 완료 ==="
done

log "Track 2 파이프라인 완료"
