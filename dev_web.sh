#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$ROOT_DIR/.dev_web.pid"
LOG_FILE="$ROOT_DIR/.dev_web.log"

ACTION="restart"
HOST="0.0.0.0"
PORT="8888"
RELOAD="false"

usage() {
  cat <<'EOF'
Usage:
  ./dev_web.sh [start|stop|restart|status] [--reload] [--host HOST] [--port PORT]

Examples:
  ./dev_web.sh start --reload
  ./dev_web.sh restart --port 8888
  ./dev_web.sh stop
EOF
}

if [[ "${1:-}" =~ ^(start|stop|restart|status)$ ]]; then
  ACTION="$1"
  shift
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reload)
      RELOAD="true"
      shift
      ;;
    --host)
      HOST="${2:-}"
      shift 2
      ;;
    --port)
      PORT="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

is_running() {
  [[ -f "$PID_FILE" ]] || return 1
  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [[ -n "$pid" ]] || return 1
  kill -0 "$pid" 2>/dev/null
}

stop_app() {
  if ! is_running; then
    rm -f "$PID_FILE"
    echo "web_app is not running."
    return 0
  fi

  local pid
  pid="$(cat "$PID_FILE")"
  echo "Stopping web_app (pid=$pid)..."
  kill "$pid" 2>/dev/null || true

  for _ in {1..20}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$PID_FILE"
      echo "Stopped."
      return 0
    fi
    sleep 0.2
  done

  echo "Force killing web_app (pid=$pid)..."
  kill -9 "$pid" 2>/dev/null || true
  rm -f "$PID_FILE"
  echo "Stopped (forced)."
}

start_app() {
  if is_running; then
    echo "web_app is already running (pid=$(cat "$PID_FILE"))."
    return 0
  fi

  if [[ -f "$ROOT_DIR/.venv/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source "$ROOT_DIR/.venv/bin/activate"
  fi

  local cmd=()
  if [[ "$RELOAD" == "true" ]]; then
    cmd=(flask --app web_app:app run --host "$HOST" --port "$PORT" --debug)
  else
    cmd=(python3 "$ROOT_DIR/web_app.py" --host "$HOST" --port "$PORT")
  fi

  echo "Starting web_app on ${HOST}:${PORT} (reload=${RELOAD})..."
  nohup "${cmd[@]}" >>"$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"
  echo "Started (pid=$(cat "$PID_FILE")). Log: $LOG_FILE"
}

status_app() {
  if is_running; then
    echo "Running (pid=$(cat "$PID_FILE"))."
  else
    echo "Not running."
  fi
}

case "$ACTION" in
  start)
    start_app
    ;;
  stop)
    stop_app
    ;;
  restart)
    stop_app
    start_app
    ;;
  status)
    status_app
    ;;
esac
