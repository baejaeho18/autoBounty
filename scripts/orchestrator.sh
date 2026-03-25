#!/usr/bin/env bash
# ============================================================
# Bounty Autopilot — Orchestrator
# cron entry: 0 6 * * * ~/bounty-autopilot/scripts/orchestrator.sh
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$BASE/logs"
DATE=$(date +%Y-%m-%d)
CONFIG="$BASE/config.json"

mkdir -p "$LOG_DIR"

log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG_DIR/$DATE-orchestrator.log"; }

# ─── 중복 실행 방지 ───
LOCKFILE="$BASE/.orchestrator.lock"
if [[ -f "$LOCKFILE" ]]; then
  LOCK_PID=$(cat "$LOCKFILE" 2>/dev/null || echo "")
  if [[ -n "$LOCK_PID" ]] && kill -0 "$LOCK_PID" 2>/dev/null; then
    log "ERROR: 이미 실행 중 (PID $LOCK_PID) — 종료"
    exit 1
  fi
  log "WARN: 이전 실행이 비정상 종료된 듯 — 락 파일 제거 후 계속"
  rm -f "$LOCKFILE"
fi
echo $$ > "$LOCKFILE"
trap "rm -f '$LOCKFILE'" EXIT

log "========== Bounty Autopilot 시작 =========="

# ─── config.json에서 활성화 여부 읽기 ───
track_enabled() {
  python3 -c "
import json, os
with open('$CONFIG') as f:
    cfg = json.load(f)
print(cfg.get('$1', {}).get('enabled', True))
" 2>/dev/null || echo "True"
}

PIDS=()

# ─── Track 1: IDOR/API (매일) ───
if [[ "$(track_enabled track1_idor)" == "True" ]]; then
  log "Track 1: IDOR/API 파이프라인 시작"
  bash "$BASE/scripts/track1_idor.sh" >> "$LOG_DIR/$DATE-track1.log" 2>&1 &
  PIDS+=($!)
else
  log "Track 1: config에서 비활성화됨"
fi

# ─── Track 2: OSS (매일 — 변경 없으면 자동 스킵) ───
if [[ "$(track_enabled track2_oss)" == "True" ]]; then
  log "Track 2: OSS 감사 파이프라인 시작 (변경 없는 레포는 자동 스킵)"
  bash "$BASE/scripts/track2_oss.sh" >> "$LOG_DIR/$DATE-track2.log" 2>&1 &
  PIDS+=($!)
else
  log "Track 2: config에서 비활성화됨"
fi

# ─── Track 3: Web3 (매일 — 변경 없으면 자동 스킵) ───
if [[ "$(track_enabled track3_web3)" == "True" ]]; then
  log "Track 3: Web3 감사 파이프라인 시작 (변경 없는 레포는 자동 스킵)"
  bash "$BASE/scripts/track3_web3.sh" >> "$LOG_DIR/$DATE-track3.log" 2>&1 &
  PIDS+=($!)
else
  log "Track 3: config에서 비활성화됨"
fi


# --- Track 4: ReDoS (매일 — OSS VRP 대상 정규식 취약점 스캔) ---
if [[ "$(track_enabled track4_redos)" == "True" ]]; then
  log "Track 4: ReDoS 스캐너 파이프라인 시작"
  bash "$BASE/scripts/track4_redos.sh" >> "$LOG_DIR/$DATE-track4.log" 2>&1 &
  PIDS+=($!)
else
  log "Track 4: config에서 비활성화됨"
fi

# 모든 트랙 완료 대기
FAIL=0
for pid in "${PIDS[@]}"; do
  if ! wait "$pid"; then
    log "WARN: PID $pid 실패 (exit $?)"
    FAIL=$((FAIL + 1))
  fi
done

# ─── 결과 취합 + 알림 ───
log "결과 취합 중..."
python3 "$BASE/scripts/aggregate_notify.py"

if [[ "$FAIL" -gt 0 ]]; then
  log "========== Bounty Autopilot 완료 ($FAIL개 트랙 에러 발생) =========="
else
  log "========== Bounty Autopilot 완료 =========="
fi
