#!/usr/bin/env bash
# ============================================================
# Bounty Autopilot — 원커맨드 셋업
# 실행: bash setup.sh
# ============================================================
set -euo pipefail

echo "🎯 Bounty Autopilot 설치 시작"
echo ""

# 프로젝트 루트 자동 감지
BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── 1. 디렉토리 ───
echo "[1/6] 디렉토리 생성..."
mkdir -p "$BASE"/{scripts,prompts,data/{track1/{recon,endpoints,analysis,reports},track2/{repos,scans,analysis,reports},track3/{repos,scans,analysis,reports}},logs}

# ─── 2. 실행 권한 ───
echo "[2/6] 스크립트 실행 권한 설정..."
chmod +x "$BASE"/scripts/*.sh

# ─── 3. 필수 도구 확인 ───
echo "[3/6] 필수 도구 확인..."
MISSING=""
for cmd in claude python3 git; do
  command -v $cmd &>/dev/null || MISSING="$MISSING $cmd"
done
if [[ -n "$MISSING" ]]; then
  echo "❌ 필수 도구 미설치:$MISSING"
  echo "  claude: npm install -g @anthropic-ai/claude-code"
  echo "  python3: 시스템 패키지 매니저로 설치"
  exit 1
fi

# 선택적 도구 (없어도 해당 기능만 스킵됨)
for cmd in subfinder httpx katana semgrep slither; do
  if command -v $cmd &>/dev/null; then
    echo "  ✓ $cmd"
  else
    echo "  ○ $cmd (미설치 — 해당 기능 스킵됨)"
  fi
done

# ─── 4. Python 의존성 ───
echo "[4/6] Python 의존성..."
pip3 install pip-audit 2>/dev/null || true

# ─── 5. 타겟 파일 초기화 ───
echo "[5/6] 타겟 파일 확인..."
for f in targets_idor targets_oss targets_web3; do
  if [[ ! -f "$BASE/data/${f}.json" ]]; then
    echo "[]" > "$BASE/data/${f}.json"
    echo "  생성됨: data/${f}.json (타겟 추가 필요)"
  else
    echo "  존재함: data/${f}.json"
  fi
done

# ─── 6. Cron 등록 ───
echo "[6/6] Cron 등록..."
CRON_MAIN="0 6 * * * $BASE/scripts/orchestrator.sh >> $BASE/logs/cron.log 2>&1"
CRON_DISCOVER="0 8 * * 1 $BASE/scripts/discover_targets.sh >> $BASE/logs/cron-discover.log 2>&1"
CRON_TUNE="0 9 1 * * $BASE/scripts/tune_prompts.sh >> $BASE/logs/cron-tune.log 2>&1"

CURRENT_CRON=$(crontab -l 2>/dev/null || true)

if echo "$CURRENT_CRON" | grep -qF "orchestrator.sh"; then
  echo "  이미 등록됨"
else
  echo "$CURRENT_CRON
$CRON_MAIN
$CRON_DISCOVER
$CRON_TUNE" | crontab -
  echo "  등록 완료:"
  echo "    매일 06:00 — 3개 트랙 자동 실행"
  echo "    매주 월 08:00 — 신규 타겟 탐색"
  echo "    매월 1일 09:00 — 프롬프트 자동 튜닝"
fi

echo ""
echo "═══════════════════════════════════════════"
echo "✅ 설치 완료!"
echo ""
echo "다음 단계:"
echo ""
echo "1. 타겟 추가 (필수):"
echo "   nano $BASE/data/targets_idor.json"
echo "   nano $BASE/data/targets_oss.json"
echo "   nano $BASE/data/targets_web3.json"
echo ""
echo "2. Discord 알림 설정 (선택):"
echo "   nano $BASE/config.json"
echo "   → discord_webhook 값 입력"
echo ""
echo "3. 수동 실행 테스트:"
echo "   bash $BASE/scripts/orchestrator.sh"
echo ""
echo "4. 결과 확인:"
echo "   python3 $BASE/scripts/review.py"
echo "═══════════════════════════════════════════"
