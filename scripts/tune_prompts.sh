#!/usr/bin/env bash
# ============================================================
# 프롬프트 자동 개선 — 월 1회 실행
# rejected findings 패턴을 분석해서 프롬프트를 자동 튜닝
# cron: 0 9 1 * * ~/bounty-autopilot/scripts/tune_prompts.sh
# ============================================================
set -euo pipefail

BASE="$HOME/bounty-autopilot"
DATE=$(date +%Y-%m-%d)

log() { echo "[TUNE $(date '+%H:%M:%S')] $1"; }

log "프롬프트 튜닝 시작"

# rejected findings 수집
REJECTED=$(python3 -c "
import json
with open('$BASE/data/findings.json') as f:
    db = json.load(f)
rejected = [f for f in db['findings'] if f['status'] == 'rejected']
for r in rejected[-20:]:
    print(f\"Track: {r['track']} | Type: {r['type']} | Desc: {r['description'][:150]}\")
print(f'---')
print(f'Total rejected: {len(rejected)}')
verified = [f for f in db['findings'] if f['status'] in ('verified','submitted','paid')]
print(f'Total verified: {len(verified)}')
" 2>/dev/null || echo "데이터 없음")

if [[ "$REJECTED" == "데이터 없음" ]]; then
  log "아직 rejected/verified 데이터 없음 — 스킵"
  exit 0
fi

# Claude에게 false positive 패턴 분석 + 프롬프트 개선 요청
claude -p "
당신은 버그 바운티 자동화 시스템의 프롬프트 엔지니어입니다.

아래는 최근 rejected (false positive) 된 발견사항들입니다:
$REJECTED

이 패턴을 분석해서:
1. 가장 흔한 false positive 유형 TOP 3
2. 각 유형에 대해 프롬프트에 추가할 '제외 조건'
3. 정확도를 높이기 위한 프롬프트 개선 제안

결과를 아래 JSON으로 출력:
{
  \"date\": \"$DATE\",
  \"fp_patterns\": [
    {
      \"pattern\": \"false positive 패턴 설명\",
      \"frequency\": \"빈도\",
      \"exclusion_rule\": \"프롬프트에 추가할 제외 조건 문구\"
    }
  ],
  \"prompt_improvements\": [
    \"개선할 프롬프트 문구 1\",
    \"개선할 프롬프트 문구 2\"
  ],
  \"current_fp_rate\": \"현재 false positive 비율\"
}
" > "$BASE/data/tune_${DATE}.json" 2>/dev/null || true

log "튜닝 결과: $BASE/data/tune_${DATE}.json"
log "결과를 확인하고 각 track 스크립트의 프롬프트에 반영하세요"
