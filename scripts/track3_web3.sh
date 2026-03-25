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

  # Phase 3: Slither TP/FP 판별 + 실제 코드 기반 분석
  log "Phase 3: SAST→LLM 정밀 분석 (실제 코드 포함)"

  # 실제 Solidity 코드 추출 (파일명 목록이 아니라 코드 내용)
  SOL_CODE=$(python3 - "$REPO_DIR" <<'PYEOF'
import os, sys, glob

repo_dir = sys.argv[1]
output = []
total_chars = 0

for fpath in sorted(glob.glob(os.path.join(repo_dir, '**', '*.sol'), recursive=True)):
    if '/node_modules/' in fpath or '/lib/' in fpath or '/test/' in fpath or '/mock/' in fpath:
        continue
    try:
        with open(fpath) as f:
            content = f.read()
    except:
        continue
    rel = os.path.relpath(fpath, repo_dir)
    truncated = content[:6000]
    if len(content) > 6000:
        truncated += f"\n// ... truncated ({len(content)} chars total)"
    output.append(f"### {rel}\n```solidity\n{truncated}\n```\n")
    total_chars += len(truncated)
    if total_chars > 40000 or len(output) >= 12:
        break

print("\n".join(output) if output else "Solidity 파일 없음")
PYEOF
  )

  # Slither 결과에서 코드 위치 포함한 상세 정보
  SLITHER_DETAIL=""
  if [[ -f "$SLITHER_FILE" ]]; then
    SLITHER_DETAIL=$(python3 - "$SLITHER_FILE" <<'PYEOF'
import json, sys

try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except:
    print("Slither 결과 없음")
    sys.exit(0)

results = data.get('results', {}).get('detectors', [])
if not results:
    print("Slither 결과 0건")
    sys.exit(0)

parts = []
for d in results[:15]:
    impact = d.get('impact', '?')
    check = d.get('check', '?')
    desc = d.get('description', '')[:200]
    elements = d.get('elements', [])
    locations = []
    for e in elements[:3]:
        src = e.get('source_mapping', {})
        fname = src.get('filename_short', '?')
        lines = src.get('lines', [])
        line_str = f"{lines[0]}-{lines[-1]}" if lines else "?"
        locations.append(f"{fname}:{line_str}")
    parts.append(f"- [{impact}] {check}: {desc}\n  Location: {', '.join(locations)}")

print("\n".join(parts))
PYEOF
    )
  fi

  ANALYSIS_FILE="$TRACK_DIR/analysis/${NAME}_${DATE}.json"

  claude -p "
당신은 시니어 스마트 컨트랙트 보안 연구원입니다.
프로토콜: $NAME

## 실제 컨트랙트 코드:
$SOL_CODE

## Slither 정적 분석 결과:
$SLITHER_DETAIL

위 코드를 직접 읽고 다음을 분석하세요:

1. Slither 결과 각각에 대해: 실제 코드를 확인하고 TP인지 FP인지 판별
2. Slither가 못 잡은 추가 취약점:
   - Reentrancy (external call 후 상태 변경)
   - 접근 제어 누락 (onlyOwner 등 없는 민감 함수)
   - Flash loan 공격 벡터 (가격 오라클 조작)
   - 정수 연산 반올림 오차로 인한 자금 유출
   - 초기화 함수 재호출 (프록시 패턴)
   - 자금 인출 잔액 계산 오류
   - 거버넌스 공격 (투표 조작, 타임락 우회)

중요:
- Solidity 0.8+ 기본 overflow 보호로 막히는 건 제외
- OpenZeppelin 표준 구현 그대로인 부분 제외
- 실제 코드를 근거로 판단 — 추측으로 취약점 만들지 마세요

JSON으로만 출력:
{
  \"protocol\": \"$NAME\",
  \"date\": \"$DATE\",
  \"findings\": [
    {
      \"type\": \"취약점 유형\",
      \"severity\": \"CRITICAL/HIGH/MEDIUM/LOW\",
      \"source\": \"slither_tp 또는 manual_review\",
      \"contract\": \"컨트랙트명\",
      \"function\": \"함수명\",
      \"vulnerable_code\": \"취약한 코드 라인 (실제 코드에서 인용)\",
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
