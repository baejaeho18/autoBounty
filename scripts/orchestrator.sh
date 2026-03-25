#!/usr/bin/env bash
# ============================================================
# ReDoS Scanner — Orchestrator
# cron entry: 0 6 * * * ~/autoBounty/scripts/orchestrator.sh
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

log "========== ReDoS Scanner 시작 =========="

# ─── config.json에서 활성화 여부 읽기 ───
track_enabled() {
  python3 -c "
import json
with open('$CONFIG') as f:
    cfg = json.load(f)
print(cfg.get('$1', {}).get('enabled', True))
" 2>/dev/null || echo "True"
}

# ─── ReDoS 스캔 실행 ───
if [[ "$(track_enabled track_redos)" == "True" ]]; then
  log "ReDoS 스캐너 파이프라인 시작"
  bash "$BASE/scripts/track4_redos.sh" >> "$LOG_DIR/$DATE-redos.log" 2>&1
  RESULT=$?
  if [[ "$RESULT" -ne 0 ]]; then
    log "WARN: ReDoS 스캐너 실패 (exit $RESULT)"
  fi
else
  log "ReDoS: config에서 비활성화됨"
fi

# ─── 결과 취합 + 알림 ───
log "결과 취합 중..."
python3 "$BASE/scripts/aggregate_notify.py"

log "========== ReDoS Scanner 완료 =========="
