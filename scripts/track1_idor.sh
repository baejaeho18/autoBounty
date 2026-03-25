#!/usr/bin/env bash
# ============================================================
# Track 1: IDOR / API 자동 파이프라인
# 매일 실행 — Recon → Endpoint 추출 → IDOR 후보 분석 → 자동 검증 → 리포트 초안
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$(dirname "$SCRIPT_DIR")"
TRACK_DIR="$BASE/data/track1"
TARGETS="$BASE/data/targets_idor.json"
CONFIG="$BASE/config.json"
EXTRACT_JSON="$BASE/scripts/extract_json.py"
DATE=$(date +%Y-%m-%d)

mkdir -p "$TRACK_DIR"/{recon,endpoints,analysis,reports}

log() { echo "[T1 $(date '+%H:%M:%S')] $1"; }

# config에서 rate limit 읽기
PAUSE_SEC=$(python3 -c "
import json
try:
    with open('$CONFIG') as f:
        cfg = json.load(f)
    print(cfg['general']['rate_limit']['pause_between_targets_sec'])
except: print(120)
" 2>/dev/null || echo "120")
log "Rate limit: 타겟 간 ${PAUSE_SEC}초 대기"

# ─── 타겟 목록 읽기 ───
TARGET_COUNT=$(python3 -c "
import json
with open('$TARGETS') as f:
    targets = json.load(f)
print(len(targets))
" 2>/dev/null || echo "0")

if [[ "$TARGET_COUNT" == "0" ]]; then
  log "등록된 타겟 없음 — 종료"
  exit 0
fi

TOKEN_MANAGER="$BASE/scripts/token_manager.py"

python3 -c "
import json, os, sys
sys.path.insert(0, '$BASE/scripts')

# token_manager가 있으면 사용, 없으면 기존 ENV 방식 폴백
try:
    from token_manager import get_tokens_for_domain, load_tokens
    token_store = load_tokens()
    has_token_manager = True
except:
    has_token_manager = False

with open('$TARGETS') as f:
    targets = json.load(f)
for t in targets:
    domain = t['domain']
    token_a = ''
    token_b = ''

    # 1순위: token_manager (자동 갱신 포함)
    if has_token_manager and domain in token_store:
        ta, tb = get_tokens_for_domain(domain)
        if ta: token_a = ta
        if tb: token_b = tb

    # 2순위: ENV 환경변수 (기존 방식 호환)
    if not token_a:
        env_key = t.get('auth', {}).get('user_a_token', '')
        if env_key.startswith('ENV:'):
            token_a = os.environ.get(env_key[4:], '')
    if not token_b:
        env_key = t.get('auth', {}).get('user_b_token', '')
        if env_key.startswith('ENV:'):
            token_b = os.environ.get(env_key[4:], '')

    print(f\"{domain}|{token_a}|{token_b}|{t.get('program_url','')}\")
" | while IFS='|' read -r DOMAIN TOKEN_A TOKEN_B PROGRAM_URL; do

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
  if command -v subfinder &>/dev/null; then
    if ! subfinder -d "$DOMAIN" -silent -o "$DOMAIN_DIR/subdomains_raw.txt" 2>/dev/null; then
      log "WARN: subfinder 실패 ($DOMAIN)"
    fi
  else
    log "WARN: subfinder 미설치 — 서브도메인 열거 스킵"
    echo "$DOMAIN" > "$DOMAIN_DIR/subdomains_raw.txt"
  fi

  if command -v httpx &>/dev/null && [[ -s "$DOMAIN_DIR/subdomains_raw.txt" ]]; then
    if ! cat "$DOMAIN_DIR/subdomains_raw.txt" | \
      httpx -silent -status-code -title -tech-detect \
      -o "$DOMAIN_DIR/subdomains.txt" 2>/dev/null; then
      log "WARN: httpx 실패 ($DOMAIN)"
    fi
  fi

  # 새로운 서브도메인 감지
  if [[ -f "$DOMAIN_DIR/subdomains_prev.txt" ]] && [[ -f "$DOMAIN_DIR/subdomains.txt" ]]; then
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

  if command -v katana &>/dev/null; then
    if ! echo "$DOMAIN" | katana -silent -d 3 -jc -kf all \
      -f qurl -o "$DOMAIN_DIR/endpoints_raw.txt" 2>/dev/null; then
      log "WARN: katana 실패 ($DOMAIN)"
    fi
  else
    log "WARN: katana 미설치 — 엔드포인트 크롤링 스킵"
    touch "$DOMAIN_DIR/endpoints_raw.txt"
  fi

  # API 경로만 필터링
  grep -iE "(api|v[0-9]|graphql|rest|json|users|account|profile|settings|admin)" \
    "$DOMAIN_DIR/endpoints_raw.txt" \
    > "$DOMAIN_DIR/endpoints.txt" 2>/dev/null || true

  # 새 엔드포인트 감지
  if [[ -f "$DOMAIN_DIR/endpoints_prev.txt" ]] && [[ -f "$DOMAIN_DIR/endpoints.txt" ]]; then
    NEW_ENDPOINTS=$(comm -23 \
      <(sort "$DOMAIN_DIR/endpoints.txt") \
      <(sort "$DOMAIN_DIR/endpoints_prev.txt") \
    ) || true
    if [[ -n "$NEW_ENDPOINTS" ]]; then
      log "!! 새 엔드포인트 발견: $(echo "$NEW_ENDPOINTS" | wc -l)건"
      echo "$NEW_ENDPOINTS" >> "$DOMAIN_DIR/new_endpoints_$DATE.txt"
    fi
  fi

  # 엔드포인트가 없으면 다음 타겟으로
  if [[ ! -s "$DOMAIN_DIR/endpoints.txt" ]]; then
    log "엔드포인트 없음 — $DOMAIN 스킵"
    continue
  fi

  # ──────────────────────────────────────
  # Phase 3: Claude 분석 — 자동 (claude -p)
  # ──────────────────────────────────────
  log "Phase 3: Claude Code로 IDOR 후보 분석"

  ALLOWED_TOOLS="Read,Grep,Glob,Bash(ls:*),Bash(head:*),Bash(wc:*)"
  ENDPOINTS_FILE="$DOMAIN_DIR/endpoints.txt"
  ANALYSIS_FILE="$TRACK_DIR/analysis/${DOMAIN}_${DATE}.json"

  claude -p "
당신은 버그 바운티 보안 연구원입니다. $DOMAIN 에서 수집된 API 엔드포인트를 분석합니다.

엔드포인트 파일: $ENDPOINTS_FILE

**지시사항:**
1. Read 도구로 엔드포인트 파일을 전체 읽으세요
2. 사용자 ID, 리소스 ID, 또는 예측 가능한 식별자를 파라미터로 받는 엔드포인트를 찾으세요
3. 각 엔드포인트에 대해 IDOR 가능성을 HIGH/MEDIUM/LOW로 평가하세요
4. 구체적인 테스트 시나리오를 작성하세요 (어떤 ID를 바꿔서 어떤 데이터 접근을 시도할지)
5. 보안 미들웨어가 정상 작동할 경우 막히는 케이스는 제외하세요 (false positive 줄이기)
6. rate-limited 엔드포인트도 제외하세요

최종 결과를 반드시 아래 JSON 형식으로만 출력하세요:
{
  \"domain\": \"$DOMAIN\",
  \"date\": \"$DATE\",
  \"candidates\": [
    {
      \"endpoint\": \"URL\",
      \"method\": \"GET/POST/PUT/DELETE\",
      \"param\": \"변경할 파라미터\",
      \"severity\": \"HIGH/MEDIUM/LOW\",
      \"test_scenario\": \"테스트 방법 설명\",
      \"impact\": \"성공 시 영향\",
      \"curl_test_a\": \"User A로 리소스 생성/조회하는 curl 명령\",
      \"curl_test_b\": \"User B 토큰으로 User A 리소스 접근 시도하는 curl 명령\"
    }
  ]
}
" --allowedTools "$ALLOWED_TOOLS" 2>/dev/null | python3 "$EXTRACT_JSON" > "$ANALYSIS_FILE"

  # JSON 추출 실패 체크
  if python3 -c "import json; d=json.load(open('$ANALYSIS_FILE')); assert 'error' not in d" 2>/dev/null; then
    log "Phase 3 완료: 분석 결과 저장됨"
  else
    log "WARN: Claude JSON 파싱 실패 — $DOMAIN Phase 3 결과 불완전"
    continue
  fi

  # ──────────────────────────────────────
  # Phase 3.5: 자동 IDOR 검증 (토큰이 있을 때만)
  # ──────────────────────────────────────
  if [[ -n "$TOKEN_A" ]] && [[ -n "$TOKEN_B" ]]; then
    log "Phase 3.5: 토큰 기반 자동 IDOR 검증"

    python3 - "$ANALYSIS_FILE" "$TOKEN_A" "$TOKEN_B" "$DOMAIN_DIR" "$DATE" <<'PYEOF'
import json, sys, subprocess, os, hashlib

analysis_file, token_a, token_b, domain_dir, date = sys.argv[1:6]

with open(analysis_file) as f:
    data = json.load(f)

results = []
for c in data.get("candidates", []):
    if c.get("severity") != "HIGH":
        continue

    endpoint = c.get("endpoint", "")
    method = c.get("method", "GET").upper()
    if not endpoint.startswith("http"):
        continue

    # User A로 요청 — 응답 body + status code 캡처
    cmd_a = ["curl", "-s", "-w", "\n__STATUS__%{http_code}",
             "-H", f"Authorization: {token_a}", "-X", method, endpoint]
    # User B로 동일 엔드포인트 요청
    cmd_b = ["curl", "-s", "-w", "\n__STATUS__%{http_code}",
             "-H", f"Authorization: {token_b}", "-X", method, endpoint]

    try:
        res_a = subprocess.run(cmd_a, capture_output=True, text=True, timeout=15)
        res_b = subprocess.run(cmd_b, capture_output=True, text=True, timeout=15)

        # 응답 파싱: body와 status code 분리
        raw_a = res_a.stdout.rsplit("\n__STATUS__", 1)
        raw_b = res_b.stdout.rsplit("\n__STATUS__", 1)
        body_a = raw_a[0] if len(raw_a) > 1 else ""
        code_a = raw_a[1].strip() if len(raw_a) > 1 else "?"
        body_b = raw_b[0] if len(raw_b) > 1 else ""
        code_b = raw_b[1].strip() if len(raw_b) > 1 else "?"

        # IDOR 판정 로직 (3단계)
        idor_confidence = "none"
        idor_evidence = ""

        if code_a == "200" and code_b == "200":
            # Level 1: 둘 다 200 → 후보
            idor_confidence = "low"
            idor_evidence = "Both returned 200"

            # Level 2: 응답 body에 User A 고유 데이터가 User B에게도 보이는지
            try:
                json_a = json.loads(body_a)
                json_b = json.loads(body_b)

                # 응답이 동일하면 (같은 데이터 반환) IDOR 확정도 높음
                if body_a.strip() == body_b.strip():
                    idor_confidence = "high"
                    idor_evidence = "Identical response body — User B sees User A's data"
                # 응답 구조가 같고 내용이 있으면 (에러 응답이 아님)
                elif set(json_a.keys()) == set(json_b.keys()) and len(body_a) > 50:
                    idor_confidence = "medium"
                    idor_evidence = "Same response structure with data (not error page)"
            except (json.JSONDecodeError, AttributeError):
                # JSON이 아닌 응답도 크기 비교
                if abs(len(body_a) - len(body_b)) < 100 and len(body_a) > 50:
                    idor_confidence = "medium"
                    idor_evidence = "Similar response size (non-JSON)"

        elif code_a == "200" and code_b in ("401", "403"):
            idor_confidence = "none"
            idor_evidence = f"Properly blocked (User B got {code_b})"

        # 증거 파일 저장 (high/medium만)
        evidence_dir = os.path.join(domain_dir, "evidence")
        evidence_paths = {}
        if idor_confidence in ("high", "medium"):
            os.makedirs(evidence_dir, exist_ok=True)
            safe_endpoint = hashlib.md5(endpoint.encode()).hexdigest()[:8]
            for label, code, body in [("user_a", code_a, body_a), ("user_b", code_b, body_b)]:
                epath = os.path.join(evidence_dir, f"{date}_{safe_endpoint}_{label}.txt")
                with open(epath, "w") as ef:
                    ef.write(f"Endpoint: {method} {endpoint}\n")
                    ef.write(f"Status: {code}\n")
                    ef.write(f"---\n{body[:5000]}\n")
                evidence_paths[label] = epath

        results.append({
            "endpoint": endpoint,
            "method": method,
            "status_user_a": code_a,
            "status_user_b": code_b,
            "idor_confidence": idor_confidence,
            "idor_evidence": idor_evidence,
            "evidence_files": evidence_paths,
            "response_size_a": len(body_a),
            "response_size_b": len(body_b),
            "original_severity": c.get("severity"),
        })
    except Exception as e:
        results.append({"endpoint": endpoint, "error": str(e)})

output_path = os.path.join(domain_dir, f"idor_verify_{date}.json")
verified_count = sum(1 for r in results if r.get("idor_confidence") in ("high", "medium"))
with open(output_path, "w") as f:
    json.dump({"results": results, "verified_count": verified_count}, f, indent=2, ensure_ascii=False)

# 결과 요약
high_count = sum(1 for r in results if r.get("idor_confidence") == "high")
med_count = sum(1 for r in results if r.get("idor_confidence") == "medium")
print(f"[T1] 자동 검증: {len(results)}건 테스트, IDOR 확신 {high_count}건 / 의심 {med_count}건")
PYEOF
  else
    log "Phase 3.5: 인증 토큰 미설정 — 자동 검증 스킵 (수동 검증 필요)"
  fi

  # ──────────────────────────────────────
  # Phase 4: 리포트 초안 — 자동
  # ──────────────────────────────────────
  log "Phase 4: HIGH 심각도 건에 대해 리포트 초안 생성"

  HIGH_COUNT=$(python3 -c "
import json
try:
    with open('$ANALYSIS_FILE') as f:
        data = json.load(f)
    highs = [c for c in data.get('candidates', []) if c.get('severity') == 'HIGH']
    print(len(highs))
except: print(0)
" 2>/dev/null || echo "0")

  if [[ "$HIGH_COUNT" -gt 0 ]]; then
    log "!! HIGH 심각도 $HIGH_COUNT건 발견 — 리포트 초안 생성"

    ANALYSIS=$(cat "$ANALYSIS_FILE")

    # 자동 검증 결과가 있으면 포함
    VERIFY_INFO=""
    VERIFY_FILE="$DOMAIN_DIR/idor_verify_${DATE}.json"
    if [[ -f "$VERIFY_FILE" ]]; then
      VERIFY_INFO="

## 자동 검증 결과:
$(cat "$VERIFY_FILE")
"
    fi

    REPORT_FILE="$TRACK_DIR/reports/${DOMAIN}_${DATE}_report.md"

    claude -p "
아래 IDOR 분석 결과 중 severity가 HIGH인 항목에 대해
HackerOne 버그 바운티 리포트 초안을 작성해주세요.

$ANALYSIS
$VERIFY_INFO

각 리포트는 다음 형식으로:
## 제목
## 요약 (2문장)
## 영향도
## 재현 단계 (step-by-step, curl 예시 포함 — Authorization 헤더에 실제 토큰 대신 \$TOKEN_A, \$TOKEN_B 플레이스홀더 사용)
## CVSS 3.1 예상 점수
## 수정 권고사항
" > "$REPORT_FILE" 2>/dev/null

    if [[ -s "$REPORT_FILE" ]]; then
      python3 "$BASE/scripts/add_finding.py" \
        --track "idor" \
        --domain "$DOMAIN" \
        --file "$ANALYSIS_FILE" \
        --report "$REPORT_FILE"
      log "리포트 저장: $REPORT_FILE"
    else
      log "WARN: 리포트 생성 실패"
    fi
  else
    log "HIGH 심각도 건 없음 — 리포트 스킵"
  fi

  # config 기반 rate limit
  log "다음 타겟까지 ${PAUSE_SEC}초 대기"
  sleep "$PAUSE_SEC"

  log "=== $DOMAIN 완료 ==="
done

log "Track 1 파이프라인 완료"
