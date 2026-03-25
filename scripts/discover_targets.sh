#!/usr/bin/env bash
# ============================================================
# 자동 타겟 발견 — 주 1회 실행
# 새로 등록된 버그 바운티 프로그램을 자동으로 탐색
# cron: 0 8 * * 1 ~/bounty-autopilot/scripts/discover_targets.sh
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$(dirname "$SCRIPT_DIR")"
DATE=$(date +%Y-%m-%d)

log() { echo "[DISCOVER $(date '+%H:%M:%S')] $1"; }

log "새 타겟 탐색 시작"

# ─── HackerOne 신규 프로그램 탐색 (Claude 활용) ───
claude -p "
HackerOne와 Bugcrowd에서 최근 등록된 버그 바운티 프로그램 중
다음 조건에 맞는 프로그램을 웹 검색으로 찾아줘:

조건:
1. API 엔드포인트가 스코프에 포함
2. 바운티 금액 최소 \$100+
3. 무료 회원가입 가능한 SaaS 서비스
4. 최근 3개월 내 등록 또는 스코프 확장

결과를 JSON으로만 출력:
{
  \"discovered\": \"$DATE\",
  \"programs\": [
    {
      \"name\": \"프로그램명\",
      \"platform\": \"hackerone 또는 bugcrowd\",
      \"url\": \"프로그램 URL\",
      \"domain\": \"주요 도메인\",
      \"bounty_range\": \"바운티 범위\",
      \"api_in_scope\": true,
      \"notes\": \"특이사항\"
    }
  ]
}
" > "$BASE/data/discovered_${DATE}.json" 2>/dev/null || true

# ─── Immunefi 신규 Web3 프로그램 탐색 ───
claude -p "
Immunefi에서 최근 등록된 스마트 컨트랙트 버그 바운티 중
다음 조건에 맞는 프로그램을 찾아줘:

조건:
1. Critical 바운티 \$10,000+
2. Solidity 기반
3. GitHub에 코드 공개
4. 최근 3개월 내 등록

JSON으로만 출력:
{
  \"discovered\": \"$DATE\",
  \"programs\": [
    {
      \"name\": \"프로토콜명\",
      \"platform\": \"immunefi\",
      \"url\": \"프로그램 URL\",
      \"repo_url\": \"GitHub URL\",
      \"bounty_critical\": \"Critical 바운티 금액\",
      \"tvl\": \"TVL 추정\",
      \"audit_count\": 0,
      \"notes\": \"\"
    }
  ]
}
" >> "$BASE/data/discovered_${DATE}.json" 2>/dev/null || true

# ─── GitHub 신규 오픈소스 타겟 탐색 ───
claude -p "
GitHub에서 버그 바운티/보안 감사 대상으로 적합한
오픈소스 웹 프로젝트를 찾아줘:

조건:
1. Stars 1,000~15,000
2. 웹 애플리케이션 (Python/Node.js/Ruby/Go)
3. 최근 3개월 내 활발한 커밋
4. SECURITY.md 또는 보안 정책이 있는 프로젝트
5. 인증/인가 로직이 복잡한 프로젝트

JSON으로만 출력:
{
  \"discovered\": \"$DATE\",
  \"projects\": [
    {
      \"name\": \"프로젝트명\",
      \"repo_url\": \"GitHub URL\",
      \"language\": \"언어\",
      \"stars\": 0,
      \"security_policy\": true,
      \"attack_surface_score\": \"HIGH/MEDIUM/LOW\",
      \"notes\": \"\"
    }
  ]
}
" >> "$BASE/data/discovered_${DATE}.json" 2>/dev/null || true

log "탐색 완료 → $BASE/data/discovered_${DATE}.json"
log "리뷰 후 add_target.py로 등록하세요"
