#!/usr/bin/env bash
# ============================================================
# Track 3: Web3 스마트 컨트랙트 자동 감사 파이프라인
# 화/금 실행 — Clone → Slither → Claude 분석 → PoC 초안 → 리포트
# ============================================================
set -euo pipefail

BASE="$HOME/bounty-autopilot"
TRACK_DIR="$BASE/data/track3"
TARGETS="$BASE/data/targets_web3.json"
DATE=$(date +%Y-%m-%d)

mkdir -p "$TRACK_DIR"/{repos,scans,analysis,reports,pocs}

log() { echo "[T3 $(date '+%H:%M:%S')] $1"; }

python3 -c "
import json
with open('$TARGETS') as f:
    targets = json.load(f)
for t in targets:
    print(f\"{t['repo_url']}|{t['name']}|{t.get('platform','immunefi')}\")
" | while IFS='|' read -r REPO_URL NAME PLATFORM; do

  log "=== $NAME 감사 시작 ==="
  REPO_DIR="$TRACK_DIR/repos/$NAME"

  # Phase 1: Clone/Pull
  if [[ -d "$REPO_DIR/.git" ]]; then
    cd "$REPO_DIR"
    PREV=$(git rev-parse HEAD)
    git pull --quiet 2>/dev/null || true
    [[ "$PREV" == "$(git rev-parse HEAD)" ]] && { log "변경 없음 — 스킵"; continue; }
  else
    git clone "$REPO_URL" "$REPO_DIR" 2>/dev/null || true
    cd "$REPO_DIR"
  fi

  # Phase 2: Slither 정적 분석
  log "Phase 2: Slither 정적 분석"
  slither . --json "$TRACK_DIR/scans/${NAME}_slither_${DATE}.json" 2>/dev/null || true

  SLITHER_HIGH=$(python3 -c "
import json
try:
    with open('$TRACK_DIR/scans/${NAME}_slither_${DATE}.json') as f:
        data = json.load(f)
    results = data.get('results', {}).get('detectors', [])
    high = [r for r in results if r.get('impact') in ('High', 'Medium')]
    print(len(high))
except: print(0)
" 2>/dev/null || echo "0")
  log "Slither: High/Medium ${SLITHER_HIGH}건"

  # Phase 3: Claude 심층 DeFi 분석
  log "Phase 3: Claude DeFi 보안 분석"

  # 컨트랙트 파일 목록
  SOL_FILES=$(find "$REPO_DIR" -name "*.sol" -not -path "*/node_modules/*" -not -path "*/lib/*" | head -15 | tr '\n' ',' || echo "없음")

  SLITHER_SUMMARY=$(python3 -c "
import json
try:
    with open('$TRACK_DIR/scans/${NAME}_slither_${DATE}.json') as f:
        data = json.load(f)
    for d in data.get('results',{}).get('detectors',[])[:10]:
        print(f\"- [{d.get('impact','?')}] {d.get('check','?')}: {d.get('description','')[:100]}\")
except: pass
" 2>/dev/null || echo "Slither 결과 없음")

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
" > "$TRACK_DIR/analysis/${NAME}_${DATE}.json" 2>/dev/null || true

  # Phase 4: PoC 초안 + 리포트
  CRIT_COUNT=$(python3 -c "
import json
try:
    with open('$TRACK_DIR/analysis/${NAME}_${DATE}.json') as f:
        data = json.load(f)
    crits = [f for f in data.get('findings', []) if f.get('severity') in ('CRITICAL', 'HIGH')]
    print(len(crits))
except: print(0)
" 2>/dev/null || echo "0")

  if [[ "$CRIT_COUNT" -gt 0 ]]; then
    log "!! CRITICAL/HIGH $CRIT_COUNT건 — PoC + 리포트 생성"

    ANALYSIS=$(cat "$TRACK_DIR/analysis/${NAME}_${DATE}.json")

    claude -p "
아래 스마트 컨트랙트 감사 결과의 CRITICAL/HIGH 건에 대해:

$ANALYSIS

각 건에 대해 Foundry PoC 테스트 코드를 작성하세요:
- forge test로 실행 가능한 완전한 Solidity 테스트
- 메인넷 fork 설정 포함
- 공격 전후 잔액 비교로 영향도 증명
- 각 PoC를 별도 코드 블록으로

그리고 Immunefi 리포트 형식으로 전체 리포트도 작성하세요.
" > "$TRACK_DIR/reports/${NAME}_${DATE}_report.md" 2>/dev/null || true

    python3 "$BASE/scripts/add_finding.py" \
      --track "web3" \
      --domain "$NAME" \
      --file "$TRACK_DIR/analysis/${NAME}_${DATE}.json" \
      --report "$TRACK_DIR/reports/${NAME}_${DATE}_report.md"
  fi

  log "=== $NAME 완료 ==="
done

log "Track 3 파이프라인 완료"
