#!/usr/bin/env bash
# ============================================================
# ReDoS Scanner — Daemon Orchestrator
# 한 번 실행하면 중지 전까지 백그라운드에서 계속 돌아감
#
# 사용법:
#   ./orchestrator.sh              # 포그라운드 실행
#   ./orchestrator.sh --daemon     # 백그라운드 데몬 실행
#   ./orchestrator.sh --stop       # 데몬 중지
#   ./orchestrator.sh --status     # 상태 확인
#
# 동작:
#   65개 전체 레포 순회 → 정적 분석 → LLM 분석 → 리포트
#   → CYCLE_INTERVAL_MIN 대기 → 다시 순회 (무한 반복)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$BASE/logs"
CONFIG="$BASE/config.json"
PIDFILE="$BASE/.orchestrator.pid"
STATUSFILE="$BASE/.orchestrator.status"

# 설정: 사이클 간격 (분) — config.json 또는 환경변수로 오버라이드
CYCLE_INTERVAL_MIN=${CYCLE_INTERVAL_MIN:-$(python3 -c "
import json
try:
    with open('$CONFIG') as f:
        cfg = json.load(f)
    print(cfg.get('track_redos', {}).get('cycle_interval_min', 360))
except: print(360)
" 2>/dev/null || echo "360")}

mkdir -p "$LOG_DIR"

# ─── 명령어 처리 ───
case "${1:-}" in
  --stop)
    if [[ -f "$PIDFILE" ]]; then
      PID=$(cat "$PIDFILE")
      if kill -0 "$PID" 2>/dev/null; then
        echo "데몬 중지 중 (PID $PID)..."
        kill "$PID"
        # 자식 프로세스(track4_redos.sh 등)도 정리
        pkill -P "$PID" 2>/dev/null || true
        rm -f "$PIDFILE"
        echo "중지 완료"
      else
        echo "PID $PID는 이미 종료됨 — PID 파일 정리"
        rm -f "$PIDFILE"
      fi
    else
      echo "실행 중인 데몬 없음"
    fi
    exit 0
    ;;
  --status)
    if [[ -f "$PIDFILE" ]]; then
      PID=$(cat "$PIDFILE")
      if kill -0 "$PID" 2>/dev/null; then
        echo "실행 중 (PID $PID)"
        if [[ -f "$STATUSFILE" ]]; then
          cat "$STATUSFILE"
        fi
      else
        echo "PID $PID가 종료됨 (좀비 PID 파일)"
        rm -f "$PIDFILE"
      fi
    else
      echo "실행 중인 데몬 없음"
    fi
    exit 0
    ;;
  --daemon)
    # 백그라운드 데몬 모드
    echo "데몬 모드로 시작..."
    nohup "$0" --run >> "$LOG_DIR/daemon.log" 2>&1 &
    DAEMON_PID=$!
    echo "$DAEMON_PID" > "$PIDFILE"
    echo "데몬 시작 (PID $DAEMON_PID)"
    echo "로그: $LOG_DIR/daemon.log"
    echo "중지: $0 --stop"
    exit 0
    ;;
  --run|"")
    # 실제 실행 (포그라운드 또는 --daemon에서 호출)
    ;;
  *)
    echo "사용법: $0 [--daemon|--stop|--status]"
    exit 1
    ;;
esac

# ─── 중복 실행 방지 ───
if [[ -f "$PIDFILE" ]]; then
  EXISTING_PID=$(cat "$PIDFILE" 2>/dev/null || echo "")
  if [[ -n "$EXISTING_PID" ]] && [[ "$EXISTING_PID" != "$$" ]] && kill -0 "$EXISTING_PID" 2>/dev/null; then
    echo "ERROR: 이미 실행 중 (PID $EXISTING_PID) — 종료"
    exit 1
  fi
fi
echo $$ > "$PIDFILE"

# ─── 시그널 핸들러 (graceful shutdown) ───
SHUTDOWN=false
cleanup() {
  SHUTDOWN=true
  echo ""
  log "SIGTERM/SIGINT 수신 — 현재 작업 완료 후 종료합니다..."
  # 자식 프로세스에도 전파하지 않음 (현재 스캔이 끝나면 종료)
}
trap cleanup SIGTERM SIGINT

final_cleanup() {
  rm -f "$PIDFILE" "$STATUSFILE"
  log "데몬 종료"
}
trap final_cleanup EXIT

# ─── 로그 함수 ───
log() {
  local DATE_NOW
  DATE_NOW=$(date '+%Y-%m-%d')
  echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG_DIR/$DATE_NOW-orchestrator.log"
}

update_status() {
  cat > "$STATUSFILE" << EOF
cycle: $CYCLE_NUM
state: $1
last_update: $(date '+%Y-%m-%d %H:%M:%S')
repos_total: 65
cycle_interval: ${CYCLE_INTERVAL_MIN}분
next_cycle: $2
EOF
}

# ─── config.json에서 활성화 여부 읽기 ───
track_enabled() {
  python3 -c "
import json
with open('$CONFIG') as f:
    cfg = json.load(f)
print(cfg.get('$1', {}).get('enabled', True))
" 2>/dev/null || echo "True"
}

# ══════════════════════════════════════
# 메인 루프: 중지될 때까지 반복
# ══════════════════════════════════════
CYCLE_NUM=0

log "══════════════════════════════════════════════"
log "ReDoS Scanner 데몬 시작 (PID $$)"
log "  전체 레포: 65개"
log "  사이클 간격: ${CYCLE_INTERVAL_MIN}분"
log "  중지: kill $$ 또는 orchestrator.sh --stop"
log "══════════════════════════════════════════════"

while true; do
  # 종료 신호 확인
  if [[ "$SHUTDOWN" == "true" ]]; then
    log "종료 신호 감지 — 루프 탈출"
    break
  fi

  CYCLE_NUM=$((CYCLE_NUM + 1))
  CYCLE_START=$(date +%s)
  DATE=$(date +%Y-%m-%d)

  log "══════════════════════════════════════════════"
  log "사이클 #${CYCLE_NUM} 시작 ($(date '+%Y-%m-%d %H:%M:%S'))"
  log "══════════════════════════════════════════════"

  update_status "scanning" "-"

  # ─── ReDoS 스캔 실행 ───
  if [[ "$(track_enabled track_redos)" == "True" ]]; then
    log "ReDoS 스캐너 파이프라인 시작 (65개 레포 전체)"
    bash "$BASE/scripts/track4_redos.sh" >> "$LOG_DIR/$DATE-redos.log" 2>&1
    RESULT=$?
    if [[ "$RESULT" -ne 0 ]]; then
      log "WARN: ReDoS 스캐너 실패 (exit $RESULT)"
    else
      log "ReDoS 스캐너 완료"
    fi
  else
    log "ReDoS: config에서 비활성화됨"
  fi

  # ─── 결과 취합 + 알림 ───
  log "결과 취합 중..."
  python3 "$BASE/scripts/aggregate_notify.py" 2>/dev/null || log "WARN: 결과 취합 실패"

  # ─── 사이클 완료 로그 ───
  CYCLE_END=$(date +%s)
  CYCLE_DURATION=$(( (CYCLE_END - CYCLE_START) / 60 ))
  NEXT_TIME=$(date -d "+${CYCLE_INTERVAL_MIN} minutes" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || \
              date -v+${CYCLE_INTERVAL_MIN}M '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "?")

  log "══════════════════════════════════════════════"
  log "사이클 #${CYCLE_NUM} 완료 (소요: ${CYCLE_DURATION}분)"
  log "다음 사이클: ${NEXT_TIME} (${CYCLE_INTERVAL_MIN}분 후)"
  log "══════════════════════════════════════════════"

  update_status "waiting" "$NEXT_TIME"

  # ─── 대기 (1분 단위로 나눠서 종료 신호 체크) ───
  WAIT_SECONDS=$((CYCLE_INTERVAL_MIN * 60))
  WAITED=0
  while [[ $WAITED -lt $WAIT_SECONDS ]]; do
    if [[ "$SHUTDOWN" == "true" ]]; then
      log "대기 중 종료 신호 감지 — 즉시 종료"
      break 2  # while + while 둘 다 탈출
    fi
    sleep 60
    WAITED=$((WAITED + 60))
  done
done

log "══════════════════════════════════════════════"
log "ReDoS Scanner 데몬 종료 (총 ${CYCLE_NUM} 사이클 실행)"
log "══════════════════════════════════════════════"
