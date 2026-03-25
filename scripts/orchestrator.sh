#!/usr/bin/env bash
# ============================================================
# Bounty Autopilot — Orchestrator
# cron entry: 0 6 * * * ~/bounty-autopilot/scripts/orchestrator.sh
# ============================================================
set -euo pipefail

BASE="$HOME/bounty-autopilot"
LOG_DIR="$BASE/logs"
DATE=$(date +%Y-%m-%d)
DAYOFWEEK=$(date +%u)  # 1=Mon, 7=Sun

mkdir -p "$LOG_DIR"

log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG_DIR/$DATE-orchestrator.log"; }

log "========== Bounty Autopilot 시작 =========="

# ─── Track 1: IDOR/API (매일) ───
log "Track 1: IDOR/API 파이프라인 시작"
bash "$BASE/scripts/track1_idor.sh" >> "$LOG_DIR/$DATE-track1.log" 2>&1 &
PID_T1=$!

# ─── Track 2: OSS (월/목) ───
if [[ "$DAYOFWEEK" == "1" || "$DAYOFWEEK" == "4" ]]; then
  log "Track 2: OSS 감사 파이프라인 시작"
  bash "$BASE/scripts/track2_oss.sh" >> "$LOG_DIR/$DATE-track2.log" 2>&1 &
  PID_T2=$!
else
  log "Track 2: 오늘은 스킵 (월/목에 실행)"
  PID_T2=""
fi

# ─── Track 3: Web3 (화/금) ───
if [[ "$DAYOFWEEK" == "2" || "$DAYOFWEEK" == "5" ]]; then
  log "Track 3: Web3 감사 파이프라인 시작"
  bash "$BASE/scripts/track3_web3.sh" >> "$LOG_DIR/$DATE-track3.log" 2>&1 &
  PID_T3=$!
else
  log "Track 3: 오늘은 스킵 (화/금에 실행)"
  PID_T3=""
fi

# 모든 트랙 완료 대기
wait $PID_T1
[[ -n "${PID_T2:-}" ]] && wait $PID_T2
[[ -n "${PID_T3:-}" ]] && wait $PID_T3

# ─── 결과 취합 + 알림 ───
log "결과 취합 중..."
python3 "$BASE/scripts/aggregate_notify.py"

log "========== Bounty Autopilot 완료 =========="
