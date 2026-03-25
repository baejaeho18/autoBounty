#!/usr/bin/env bash
# ============================================================
# Track 3: Web3 스마트 컨트랙트 자동 감사 파이프라인
# 매일 실행 — Clone → 변경 감지 → Slither → Claude 분석 → PoC 초안 → 리포트
# (변경 없는 레포는 자동 스킵)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$(dirname "$SCRIPT_DIR")"
TRACK_DIR="$BASE/data/track3"
TARGETS="$BASE/data/targets_web3.json"
CONFIG="$BASE/config.json"
EXTRACT_JSON="$BASE/scripts/extract_json.py"
DATE=$(date +%Y-%m-%d)

mkdir -p "$TRACK_DIR"/{repos,scans,analysis,reports,pocs}

log() { echo "[T3 $(date '+%H:%M:%S')] $1"; }

# 타겟 수 확인
TARGET_COUNT=$(python3 -c "
import json
with open('$TARGETS') as f:
    print(len(json.load(f)))
" 2>/dev/null || echo "0")

if [[ "$TARGET_COUNT" == "0" ]]; then
  log "등록된 Web3 타겟 없음 — 종료"
  exit 0
fi

python3 -c "
import json
with open('$TARGETS') as f:
    targets = json.load(f)
for t in targets:
    print(f\"{t['repo_url']}|{t['name']}|{t.get('platform','immunefi')}\")
" | while IFS='|' read -r REPO_URL NAME PLATFORM; do

  log "=== $NAME 감사 시작 ==="
  REPO_DIR="$TRACK_DIR/repos/$NAME"

  # Phase 1: Clone/Pull — git -C로 cd 없이 동작
  if [[ -d "$REPO_DIR/.git" ]]; then
    PREV=$(git -C "$REPO_DIR" rev-parse HEAD)
    git -C "$REPO_DIR" pull --quiet 2>/dev/null || {
      log "WARN: git pull 실패 ($NAME)"
      continue
    }
    NEW=$(git -C "$REPO_DIR" rev-parse HEAD)
    if [[ "$PREV" == "$NEW" ]]; then
      log "변경 없음 — $NAME 스킵"
      continue
    fi
    git -C "$REPO_DIR" diff --name-only "$PREV" "$NEW" > "$TRACK_DIR/scans/${NAME}_changed_${DATE}.txt"
    CHANGED_COUNT=$(wc -l < "$TRACK_DIR/scans/${NAME}_changed_${DATE}.txt")
    log "${CHANGED_COUNT}개 파일 변경 감지"
  else
    if ! git clone "$REPO_URL" "$REPO_DIR" 2>/dev/null; then
      log "ERROR: git clone 실패 ($NAME) — 스킵"
      continue
    fi
  fi

  # Phase 2: Slither 정적 분석
  log "Phase 2: Slither 정적 분석"
  SLITHER_FILE="$TRACK_DIR/scans/${NAME}_slither_${DATE}.json"
  if command -v slither &>/dev/null; then
    # subshell로 cd 격리
    (cd "$REPO_DIR" && slither . --json "$SLITHER_FILE" 2>/dev/null) || \
      log "WARN: Slither 스캔 실패 ($NAME)"

    if [[ -f "$SLITHER_FILE" ]]; then
      SLITHER_HIGH=$(python3 -c "
import json
try:
    with open('$SLITHER_FILE') as f:
        data = json.load(f)
    results = data.get('results', {}).get('detectors', [])
    high = [r for r in results if r.get('impact') in ('High', 'Medium')]
    print(len(high))
except: print(0)
" 2>/dev/null || echo "0")
      log "Slither: High/Medium ${SLITHER_HIGH}건"
    fi
  else
    log "WARN: slither 미설치 — 정적 분석 스킵"
  fi

  # Phase 3: Claude 심층 DeFi 분석
  log "Phase 3: Claude DeFi 보안 분석"

  SOL_FILES=$(find "$REPO_DIR" -name "*.sol" -not -path "*/node_modules/*" -not -path "*/lib/*" 2>/dev/null | head -15 | tr '\n' ',' || echo "없음")

  SLITHER_SUMMARY=""
  if [[ -f "$SLITHER_FILE" ]]; then
    SLITHER_SUMMARY=$(python3 -c "
import json
try:
    with open('$SLITHER_FILE') as f:
        data = json.load(f)
    for d in data.get('results',{}).get('detectors',[])[:10]:
        print(f\"- [{d.get('impact','?')}] {d.get('check','?')}: {d.get('description','')[:100]}\")
except: pass
" 2>/dev/null || echo "Slither 결과 없음")
  fi

  ANALYSIS_FILE="$TRACK_DIR/analysis/${NAME}_${DATE}.json"

  claude -p "
당신은 시니어 스마트 컨트랙트 보안 연구원입니다.
프로토콜: $NAME
컨트랙트 파일: $SOL_FILES

Slither 결과 요약:
$SLITHER_SUMMARY

다음을 분석하세요:
1. Reentrancy 가능 지점 (external call 후 상태 변경)
2. 접근 제어 누락 (onlyOwner 등 없는 민감 함수)
3. Flash loan 공격 벡터 (가격 오라클 조작 가능성)
4. 정수 연산 오류 (overflow/underflow, 반올림 오차)
5. 초기화 함수 재호출 가능성 (프록시 패턴)
6. 자금 인출 로직의 잔액 계산 오류
7. 거버넌스 공격 (투표 조작, 타임락 우회)

중요: Solidity 0.8+ 기본 overflow 보호 등 프레임워크 보호로 막히는 건 제외.
OpenZeppelin 표준 구현 그대로 사용하는 부분도 제외 (false positive 줄이기).

결과를 JSON으로만 출력:
{
  \"protocol\": \"$NAME\",
  \"date\": \"$DATE\",
  \"findings\": [
    {
      \"type\": \"취약점 유형\",
      \"severity\": \"CRITICAL/HIGH/MEDIUM/LOW\",
      \"contract\": \"컨트랙트명\",
      \"function\": \"함수명\",
      \"description\": \"상세 설명\",
      \"attack_scenario\": \"공격 시나리오\",
      \"estimated_impact_usd\": \"예상 피해 규모\",
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

  # Phase 4: PoC 초안 + 리포트
  CRIT_COUNT=$(python3 -c "
import json
try:
    with open('$ANALYSIS_FILE') as f:
        data = json.load(f)
    crits = [f for f in data.get('findings', []) if f.get('severity') in ('CRITICAL', 'HIGH')]
    print(len(crits))
except: print(0)
" 2>/dev/null || echo "0")

  if [[ "$CRIT_COUNT" -gt 0 ]]; then
    log "!! CRITICAL/HIGH $CRIT_COUNT건 — PoC + 리포트 생성"

    ANALYSIS=$(cat "$ANALYSIS_FILE")
    REPORT_FILE="$TRACK_DIR/reports/${NAME}_${DATE}_report.md"

    claude -p "
아래 스마트 컨트랙트 감사 결과의 CRITICAL/HIGH 건에 대해:

$ANALYSIS

각 건에 대해 Foundry PoC 테스트 코드를 작성하세요:
- forge test로 실행 가능한 완전한 Solidity 테스트
- 메인넷 fork 설정 포함
- 공격 전후 잔액 비교로 영향도 증명
- 각 PoC를 별도 코드 블록으로

그리고 Immunefi 리포트 형식으로 전체 리포트도 작성하세요.
" > "$REPORT_FILE" 2>/dev/null

    if [[ -s "$REPORT_FILE" ]]; then
      python3 "$BASE/scripts/add_finding.py" \
        --track "web3" \
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

log "Track 3 파이프라인 완료"
