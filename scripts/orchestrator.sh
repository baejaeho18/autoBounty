#!/usr/bin/env bash
# ============================================================
# ReDoS Scanner — Orchestrator
# 65개 전체 레포를 1회 순회 후 종료
#
# 사용법:
#   ./orchestrator.sh              # 포그라운드 실행 (CLI 출력 있음)
#   ./orchestrator.sh --daemon     # 백그라운드 실행 (로그 파일로만 출력)
#   ./orchestrator.sh --status     # 현재 진행 상태 확인
#   ./orchestrator.sh --stop       # 실행 중인 스캐너 중지
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$BASE/logs"
DATE=$(date +%Y-%m-%d)
CONFIG="$BASE/config.json"
LOCKFILE="$BASE/.orchestrator.lock"
STATUSFILE="$BASE/.orchestrator.status"

mkdir -p "$LOG_DIR"

# ─── 명령어 분기 (락 체크 전에 처리) ───
case "${1:-}" in
  --status)
    if [[ -f "$LOCKFILE" ]]; then
      PID=$(cat "$LOCKFILE" 2>/dev/null || echo "")
      if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
        echo "✅ 실행 중 (PID $PID)"
      else
        echo "⚠️  PID $PID 이미 종료됨 (락 파일 정리)"
        rm -f "$LOCKFILE" "$STATUSFILE"
      fi
    else
      echo "⏹️  실행 중인 스캐너 없음 (마지막 실행 결과 표시)"
    fi
    echo ""
    python3 "$SCRIPT_DIR/show_status.py" "$BASE" "$DATE"
    exit 0
    ;;
  --stop)
    if [[ -f "$LOCKFILE" ]]; then
      PID=$(cat "$LOCKFILE" 2>/dev/null || echo "")
      if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
        echo "스캐너 중지 중 (PID $PID)..."
        kill "$PID"
        pkill -P "$PID" 2>/dev/null || true
        rm -f "$LOCKFILE" "$STATUSFILE"
        echo "중지 완료"
      else
        echo "PID $PID는 이미 종료됨 — 정리"
        rm -f "$LOCKFILE" "$STATUSFILE"
      fi
    else
      echo "실행 중인 스캐너 없음"
    fi
    exit 0
    ;;
  --daemon)
    # 중복 실행 방지
    if [[ -f "$LOCKFILE" ]]; then
      EXISTING_PID=$(cat "$LOCKFILE" 2>/dev/null || echo "")
      if [[ -n "$EXISTING_PID" ]] && kill -0 "$EXISTING_PID" 2>/dev/null; then
        echo "ERROR: 이미 실행 중 (PID $EXISTING_PID)"
        echo "  상태: $0 --status"
        echo "  중지: $0 --stop"
        exit 1
      fi
    fi
    # 백그라운드로 실행 (--run 모드)
    nohup "$0" --run >> "$LOG_DIR/$DATE-orchestrator.log" 2>&1 &
    DAEMON_PID=$!
    echo "$DAEMON_PID" > "$LOCKFILE"
    echo "🚀 백그라운드 시작 (PID $DAEMON_PID)"
    echo "  로그: tail -f $LOG_DIR/$DATE-redos.log"
    echo "  상태: $0 --status"
    echo "  중지: $0 --stop"
    exit 0
    ;;
  --run)
    # 내부 사용: --daemon에서 호출되는 실제 실행 모드
    ;;
  "")
    # 포그라운드 실행
    ;;
  *)
    echo "사용법: $0 [--daemon|--status|--stop]"
    exit 1
    ;;
esac

# ─── 여기서부터 실제 실행 (포그라운드 또는 --run) ───

log() { echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG_DIR/$DATE-orchestrator.log"; }

# 중복 실행 방지 (포그라운드 모드일 때만 — --run은 이미 --daemon에서 락 잡음)
if [[ "${1:-}" != "--run" ]]; then
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
fi
trap "rm -f '$LOCKFILE' '$STATUSFILE'" EXIT

log "========== ReDoS Scanner 시작 (65개 레포 1회 순회) =========="

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
  bash "$BASE/scripts/track4_redos.sh" 2>&1 | tee -a "$LOG_DIR/$DATE-redos.log"
  RESULT=${PIPESTATUS[0]}
  if [[ "$RESULT" -ne 0 ]]; then
    log "WARN: ReDoS 스캐너 비정상 종료 (exit $RESULT)"
  fi
else
  log "ReDoS: config에서 비활성화됨"
fi

log "========== ReDoS Scanner 종료 =========="
