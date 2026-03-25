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
echo "[1/7] 디렉토리 생성..."
mkdir -p "$BASE"/{scripts,prompts,data/{track1/{recon,endpoints,analysis,reports},track2/{repos,scans,analysis,reports},track3/{repos,scans,analysis,reports}},logs}

# ─── 2. 실행 권한 ───
echo "[2/7] 스크립트 실행 권한 설정..."
chmod +x "$BASE"/scripts/*.sh 2>/dev/null || true
chmod +x "$BASE"/bounty 2>/dev/null || true

# ─── 3. 필수 도구 확인 + 설치 ───
echo "[3/7] 필수 도구 확인..."
MISSING=""
for cmd in python3 git; do
  command -v $cmd &>/dev/null || MISSING="$MISSING $cmd"
done
if [[ -n "$MISSING" ]]; then
  echo "❌ 필수 도구 미설치:$MISSING"
  echo "  python3/git: 시스템 패키지 매니저로 설치하세요"
  echo "    Ubuntu/Debian: sudo apt install python3 git"
  echo "    macOS: brew install python3 git"
  exit 1
fi

# Node.js + Claude Code CLI
if ! command -v node &>/dev/null; then
  echo "  Node.js 미설치 — 설치 중..."
  if command -v apt &>/dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - 2>/dev/null
    sudo apt install -y nodejs 2>/dev/null
  elif command -v brew &>/dev/null; then
    brew install node 2>/dev/null
  else
    echo "❌ Node.js 자동 설치 실패. 수동 설치 필요: https://nodejs.org"
    exit 1
  fi
fi

if ! command -v claude &>/dev/null; then
  echo "  Claude Code CLI 설치 중..."
  npm install -g @anthropic-ai/claude-code 2>/dev/null || {
    echo "❌ claude 설치 실패. 수동: npm install -g @anthropic-ai/claude-code"
    exit 1
  }
fi
echo "  ✓ claude ($(claude --version 2>/dev/null || echo 'installed'))"

# ─── 4. 보안 도구 자동 설치 ───
echo "[4/7] 보안 도구 설치..."

# Go 설치 확인 (subfinder, httpx, katana에 필요)
install_go_tools() {
  if ! command -v go &>/dev/null; then
    echo "  Go 미설치 — 설치 중..."
    if command -v apt &>/dev/null; then
      sudo apt install -y golang-go 2>/dev/null || {
        # apt 버전이 너무 낮으면 공식 바이너리
        GO_VERSION="1.22.4"
        curl -sL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | sudo tar -C /usr/local -xzf -
        export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
      }
    elif command -v brew &>/dev/null; then
      brew install go 2>/dev/null
    else
      echo "  ⚠ Go 자동 설치 실패 — subfinder/httpx/katana 스킵"
      return 1
    fi
  fi
  export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin
  return 0
}

# Track 1 도구: subfinder, httpx, katana
GO_AVAILABLE=false
if install_go_tools; then
  GO_AVAILABLE=true
fi

if [[ "$GO_AVAILABLE" == "true" ]]; then
  for tool_info in \
    "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" \
    "httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest" \
    "katana|github.com/projectdiscovery/katana/cmd/katana@latest"; do

    IFS='|' read -r tool_name install_path <<< "$tool_info"
    if command -v "$tool_name" &>/dev/null; then
      echo "  ✓ $tool_name"
    else
      echo "  $tool_name 설치 중..."
      if go install -v "$install_path" 2>/dev/null; then
        echo "  ✓ $tool_name 설치 완료"
      else
        echo "  ⚠ $tool_name 설치 실패 — 해당 기능 스킵됨"
      fi
    fi
  done
else
  echo "  ⚠ Go 없음 — subfinder, httpx, katana 스킵 (Track 1 일부 기능 제한)"
fi

# Playwright (IDOR 토큰 자동 추출용)
if python3 -c "import playwright" 2>/dev/null; then
  echo "  ✓ playwright"
else
  echo "  playwright 설치 중..."
  if pip3 install playwright 2>/dev/null && playwright install chromium 2>/dev/null; then
    echo "  ✓ playwright + chromium 설치 완료"
  else
    echo "  ⚠ playwright 설치 실패 — 토큰 수동 추출 필요"
  fi
fi

# Track 2 도구: semgrep, pip-audit
echo "  Python 보안 도구 설치 중..."
for pip_tool in semgrep pip-audit; do
  if command -v "$pip_tool" &>/dev/null; then
    echo "  ✓ $pip_tool"
  else
    echo "  $pip_tool 설치 중..."
    if pip3 install "$pip_tool" 2>/dev/null; then
      echo "  ✓ $pip_tool 설치 완료"
    else
      echo "  ⚠ $pip_tool 설치 실패 — 해당 기능 스킵됨"
    fi
  fi
done

# Track 3 도구: slither
if command -v slither &>/dev/null; then
  echo "  ✓ slither"
else
  echo "  slither 설치 중..."
  if pip3 install slither-analyzer 2>/dev/null; then
    echo "  ✓ slither 설치 완료"
  else
    echo "  ⚠ slither 설치 실패 — Track 3 정적 분석 스킵됨"
  fi
fi

# ─── 5. 타겟 파일 초기화 ───
echo "[5/7] 타겟 파일 확인..."
for f in targets_idor targets_oss targets_web3; do
  if [[ ! -f "$BASE/data/${f}.json" ]]; then
    echo "[]" > "$BASE/data/${f}.json"
    echo "  생성됨: data/${f}.json (타겟 추가 필요)"
  else
    echo "  존재함: data/${f}.json"
  fi
done

# ─── 6. Cron 등록 ───
echo "[6/7] Cron 등록..."
CRON_MAIN="0 6 * * * $BASE/scripts/orchestrator.sh >> $BASE/logs/cron.log 2>&1"
CRON_TOKEN="0 5 * * * python3 $BASE/scripts/token_manager.py refresh-all >> $BASE/logs/cron-token.log 2>&1"
CRON_DISCOVER="0 8 * * 1 $BASE/scripts/discover_targets.sh >> $BASE/logs/cron-discover.log 2>&1"
CRON_TUNE="0 9 1 * * $BASE/scripts/tune_prompts.sh >> $BASE/logs/cron-tune.log 2>&1"

CURRENT_CRON=$(crontab -l 2>/dev/null || true)

if echo "$CURRENT_CRON" | grep -qF "orchestrator.sh"; then
  echo "  이미 등록됨"
else
  echo "$CURRENT_CRON
$CRON_TOKEN
$CRON_MAIN
$CRON_DISCOVER
$CRON_TUNE" | crontab -
  echo "  등록 완료:"
  echo "    매일 05:00 — IDOR 토큰 자동 갱신"
  echo "    매일 06:00 — 3개 트랙 자동 실행"
  echo "    매주 월 08:00 — 신규 타겟 탐색"
  echo "    매월 1일 09:00 — 프롬프트 자동 튜닝"
fi

# ─── 7. 초회 타겟 탐색 (설치 직후 즉시 실행) ───
echo "[7/7] 초회 타겟 탐색..."

# 이전에 discover 결과가 한 번도 없으면 즉시 실행
DISCOVER_EXISTS=$(ls "$BASE"/data/discovered_*.json 2>/dev/null | head -1)
if [[ -z "$DISCOVER_EXISTS" ]]; then
  echo "  첫 설치 — 타겟 후보 탐색을 지금 실행합니다..."
  echo "  (백그라운드 실행, 결과: data/discovered_$(date +%Y-%m-%d).json)"
  nohup bash "$BASE/scripts/discover_targets.sh" \
    >> "$BASE/logs/cron-discover.log" 2>&1 &
  DISCOVER_PID=$!
  echo "  PID: $DISCOVER_PID (완료까지 수 분 소요)"
else
  echo "  기존 탐색 결과 존재 — 스킵 (다음 월요일 08:00 자동 실행)"
fi

echo ""
echo "═══════════════════════════════════════════"
echo "✅ 설치 완료!"
echo ""
echo "다음 단계:"
echo ""
echo "1. Claude 로그인 (1회):"
echo "   claude login"
echo ""
echo "2. 타겟 후보 확인 후 등록:"
echo "   cat $BASE/data/discovered_$(date +%Y-%m-%d).json"
echo "   ./bounty add-idor api.example.com https://hackerone.com/example"
echo "   ./bounty add-oss https://github.com/org/project proj python"
echo ""
echo "3. Discord 알림 설정 (선택):"
echo "   nano $BASE/config.json"
echo "   → discord_webhook 값 입력"
echo ""
echo "4. 수동 실행 테스트:"
echo "   ./bounty run"
echo ""
echo "5. 결과 확인:"
echo "   ./bounty status"
echo "═══════════════════════════════════════════"
