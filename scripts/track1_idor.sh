#!/usr/bin/env bash
# ============================================================
# Track 1: IDOR / API 자동 파이프라인
# 매일 실행 — Recon → Endpoint 추출 → IDOR 후보 분석 → 리포트 초안
# ============================================================
set -euo pipefail

BASE="$HOME/bounty-autopilot"
TRACK_DIR="$BASE/data/track1"
TARGETS="$BASE/data/targets_idor.json"
DATE=$(date +%Y-%m-%d)
FINDINGS="$BASE/data/findings.json"

mkdir -p "$TRACK_DIR"/{recon,endpoints,analysis,reports}

log() { echo "[T1 $(date '+%H:%M:%S')] $1"; }

# ─── 타겟 목록 읽기 ───
DOMAINS=$(python3 -c "
import json
with open('$TARGETS') as f:
    targets = json.load(f)
for t in targets:
    print(t['domain'])
")

for DOMAIN in $DOMAINS; do
  log "=== $DOMAIN 처리 시작 ==="
  DOMAIN_DIR="$TRACK_DIR/recon/$DOMAIN"
  mkdir -p "$DOMAIN_DIR"

  # ──────────────────────────────────────
  # Phase 1: 정찰 (Recon) — 완전 자동
  # ──────────────────────────────────────
  log "Phase 1: 서브도메인 열거"

  # 이전 결과 백업 (diff용)
  [[ -f "$DOMAIN_DIR/subdomains.txt" ]] && \
    cp "$DOMAIN_DIR/subdomains.txt" "$DOMAIN_DIR/subdomains_prev.txt"

  # subfinder → httpx (활성 도메인만)
  subfinder -d "$DOMAIN" -silent -o "$DOMAIN_DIR/subdomains_raw.txt" 2>/dev/null || true
  cat "$DOMAIN_DIR/subdomains_raw.txt" | \
    httpx -silent -status-code -title -tech-detect \
    -o "$DOMAIN_DIR/subdomains.txt" 2>/dev/null || true

  # 새로운 서브도메인 감지
  if [[ -f "$DOMAIN_DIR/subdomains_prev.txt" ]]; then
    NEW_SUBS=$(comm -23 \
      <(cut -d' ' -f1 "$DOMAIN_DIR/subdomains.txt" | sort) \
      <(cut -d' ' -f1 "$DOMAIN_DIR/subdomains_prev.txt" | sort) \
    ) || true
    if [[ -n "$NEW_SUBS" ]]; then
      log "!! 새 서브도메인 발견: $NEW_SUBS"
      echo "$NEW_SUBS" >> "$DOMAIN_DIR/new_subs_$DATE.txt"
    fi
  fi

  # ──────────────────────────────────────
  # Phase 2: API 엔드포인트 수집 — 완전 자동
  # ──────────────────────────────────────
  log "Phase 2: API 엔드포인트 크롤링"

  [[ -f "$DOMAIN_DIR/endpoints.txt" ]] && \
    cp "$DOMAIN_DIR/endpoints.txt" "$DOMAIN_DIR/endpoints_prev.txt"

  # katana로 JS 파일에서 API 경로 추출
  echo "$DOMAIN" | katana -silent -d 3 -jc -kf all \
    -f qurl -o "$DOMAIN_DIR/endpoints_raw.txt" 2>/dev/null || true

  # API 경로만 필터링
  grep -iE "(api|v[0-9]|graphql|rest|json|users|account|profile|settings|admin)" \
    "$DOMAIN_DIR/endpoints_raw.txt" \
    > "$DOMAIN_DIR/endpoints.txt" 2>/dev/null || true

  # 새 엔드포인트 감지
  if [[ -f "$DOMAIN_DIR/endpoints_prev.txt" ]]; then
    NEW_ENDPOINTS=$(comm -23 \
      <(sort "$DOMAIN_DIR/endpoints.txt") \
      <(sort "$DOMAIN_DIR/endpoints_prev.txt") \
    ) || true
    if [[ -n "$NEW_ENDPOINTS" ]]; then
      log "!! 새 엔드포인트 발견: $(echo "$NEW_ENDPOINTS" | wc -l)건"
      echo "$NEW_ENDPOINTS" >> "$DOMAIN_DIR/new_endpoints_$DATE.txt"
    fi
  fi

  # ──────────────────────────────────────
  # Phase 3: Claude 분석 — 자동 (claude -p)
  # ──────────────────────────────────────
  log "Phase 3: Claude Code로 IDOR 후보 분석"

  ENDPOINTS_CONTENT=$(head -200 "$DOMAIN_DIR/endpoints.txt" 2>/dev/null || echo "엔드포인트 없음")

  claude -p "
당신은 버그 바운티 보안 연구원입니다. 아래는 $DOMAIN 에서 수집된 API 엔드포인트 목록입니다.

$ENDPOINTS_CONTENT

다음 작업을 수행하세요:
1. 사용자 ID, 리소스 ID, 또는 예측 가능한 식별자를 파라미터로 받는 엔드포인트를 찾으세요
2. 각 엔드포인트에 대해 IDOR 가능성을 HIGH/MEDIUM/LOW로 평가하세요
3. 구체적인 테스트 시나리오를 작성하세요 (어떤 ID를 바꿔서 어떤 데이터 접근을 시도할지)

결과를 반드시 아래 JSON 형식으로만 출력하세요. 다른 텍스트는 출력하지 마세요:
{
  \"domain\": \"$DOMAIN\",
  \"date\": \"$DATE\",
  \"candidates\": [
    {
      \"endpoint\": \"URL\",
      \"param\": \"변경할 파라미터\",
      \"severity\": \"HIGH/MEDIUM/LOW\",
      \"test_scenario\": \"테스트 방법 설명\",
      \"impact\": \"성공 시 영향\"
    }
  ]
}
" > "$TRACK_DIR/analysis/${DOMAIN}_${DATE}.json" 2>/dev/null || true

  # ──────────────────────────────────────
  # Phase 4: 리포트 초안 — 자동
  # ──────────────────────────────────────
  log "Phase 4: HIGH 심각도 건에 대해 리포트 초안 생성"

  # HIGH severity 후보가 있으면 리포트 초안 작성
  HIGH_COUNT=$(python3 -c "
import json, sys
try:
    with open('$TRACK_DIR/analysis/${DOMAIN}_${DATE}.json') as f:
        data = json.load(f)
    highs = [c for c in data.get('candidates', []) if c.get('severity') == 'HIGH']
    print(len(highs))
except: print(0)
" 2>/dev/null || echo "0")

  if [[ "$HIGH_COUNT" -gt 0 ]]; then
    log "!! HIGH 심각도 $HIGH_COUNT건 발견 — 리포트 초안 생성"

    ANALYSIS=$(cat "$TRACK_DIR/analysis/${DOMAIN}_${DATE}.json")

    claude -p "
아래 IDOR 분석 결과 중 severity가 HIGH인 항목에 대해
HackerOne 버그 바운티 리포트 초안을 작성해주세요.

$ANALYSIS

각 리포트는 다음 형식으로:
## 제목
## 요약 (2문장)
## 영향도
## 재현 단계 (step-by-step, curl 예시 포함)
## CVSS 3.1 예상 점수
## 수정 권고사항

파일명: ${DOMAIN}_${DATE}_report.md
" > "$TRACK_DIR/reports/${DOMAIN}_${DATE}_report.md" 2>/dev/null || true

    # findings.json에 추가
    python3 "$BASE/scripts/add_finding.py" \
      --track "idor" \
      --domain "$DOMAIN" \
      --file "$TRACK_DIR/analysis/${DOMAIN}_${DATE}.json" \
      --report "$TRACK_DIR/reports/${DOMAIN}_${DATE}_report.md"
  fi

  # 레이트 리밋
  sleep 300

  log "=== $DOMAIN 완료 ==="
done

log "Track 1 파이프라인 완료"
