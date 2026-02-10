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

get_port_pids() {
  local pids=""
  if command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -ti "tcp:${PORT}" 2>/dev/null | tr '\n' ' ' | xargs 2>/dev/null || true)"
  fi
  if [[ -z "$pids" ]] && command -v fuser >/dev/null 2>&1; then
    pids="$(fuser -n tcp "$PORT" 2>/dev/null | tr '\n' ' ' | xargs 2>/dev/null || true)"
  fi
  echo "$pids"
}

is_running() {
  if [[ -f "$PID_FILE" ]]; then
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
  fi

  local port_pids
  port_pids="$(get_port_pids)"
  if [[ -n "$port_pids" ]]; then
    # Adopt an existing listener started outside this script.
    echo "$port_pids" | awk '{print $1}' > "$PID_FILE"
    return 0
  fi
  return 1
}

stop_app() {
  local known_pid=""
  local port_pids=""
  local target_pids=""

  if [[ -f "$PID_FILE" ]]; then
    known_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  fi
  port_pids="$(get_port_pids)"
  target_pids="$(printf "%s %s\n" "$known_pid" "$port_pids" | tr ' ' '\n' | sed '/^$/d' | sort -u | xargs 2>/dev/null || true)"

  if [[ -z "$target_pids" ]]; then
    rm -f "$PID_FILE"
    echo "web_app is not running."
    return 0
  fi

  echo "Stopping web_app (pid=${target_pids})..."
  # shellcheck disable=SC2086
  kill $target_pids 2>/dev/null || true

  local still_running=""
  for _ in {1..20}; do
    still_running=""
    for pid in $target_pids; do
      if kill -0 "$pid" 2>/dev/null; then
        still_running="${still_running} ${pid}"
      fi
    done
    if [[ -z "${still_running// }" ]]; then
      rm -f "$PID_FILE"
      echo "Stopped."
      return 0
    fi
    sleep 0.2
  done

  still_running="$(echo "$still_running" | xargs 2>/dev/null || true)"
  if [[ -n "$still_running" ]]; then
    echo "Force killing web_app (pid=${still_running})..."
    # shellcheck disable=SC2086
    kill -9 $still_running 2>/dev/null || true
  fi
  rm -f "$PID_FILE"
  echo "Stopped (forced)."
}

start_app() {
  if is_running; then
    local running_pid
    running_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    echo "web_app is already running (pid=${running_pid})."
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
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    echo "Running (pid=${pid}, port=${PORT})."
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
