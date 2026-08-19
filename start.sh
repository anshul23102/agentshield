#!/bin/bash
# AgentShield one-command startup

set -e
RESET='\033[0m'; BOLD='\033[1m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'

echo -e "${BOLD}${CYAN}"
echo "   ┌─────────────────────────────────────┐"
echo "   │   AgentShield  🛡️   v1.0.0          │"
echo "   │   Agent Security Platform            │"
echo "   └─────────────────────────────────────┘"
echo -e "${RESET}"

# ── Backend ──────────────────────────────────────────────────────────────────
echo -e "${CYAN}[1/4] Installing Python dependencies...${RESET}"
cd backend
python3 -m pip install -r requirements.txt -q

if [ ! -f ".env" ]; then
  cp .env.example .env
  echo -e "${YELLOW}  ⚠  Created backend/.env from template."
  echo -e "     Add your GITHUB_TOKEN for LLM analysis (optional).${RESET}"
fi
source .env 2>/dev/null || true

echo -e "${GREEN}[2/4] Starting AgentShield API on :${PORT:-8000}...${RESET}"
python3 run_server.py &
BACKEND_PID=$!
cd ..

# set -e can't catch a backgrounded process crashing (launching a background
# job always "succeeds" immediately, regardless of what the child does next),
# so a backend that dies on startup - bad syntax, a port already in use,
# missing deps - previously went unnoticed and the script sailed on to
# "AgentShield is running!" anyway. Give it a moment, then check it's real.
sleep 1
if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
  echo -e "${RED}  ✗  Backend process exited immediately. It likely crashed on startup - check the output above.${RESET}"
  exit 1
fi

# ── API key bootstrap ─────────────────────────────────────────────────────────
# The backend mints its own API key + admin key on first startup and writes
# them to backend/data/. Wait for that write, then wire them into the
# frontend automatically - no manual copy-pasting for a fresh clone.
echo -e "${CYAN}[3/4] Waiting for the backend to issue local API keys...${RESET}"
for i in $(seq 1 30); do
  if [ -f "backend/data/.bootstrap_api_key" ] && [ -f "backend/data/.admin_key" ]; then
    break
  fi
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    echo -e "${RED}  ✗  Backend process died while waiting for it to start up. Check the output above.${RESET}"
    exit 1
  fi
  sleep 0.5
done

if [ -f "backend/data/.bootstrap_api_key" ]; then
  BOOTSTRAP_API_KEY=$(cat backend/data/.bootstrap_api_key)
  BOOTSTRAP_ADMIN_KEY=$(cat backend/data/.admin_key 2>/dev/null || echo "")
  # Derived from the same PORT the backend itself just started on (default
  # 8000), so vite.config.js's proxy always points at the right place - this
  # file is fully regenerated below, so anything hand-edited into it (like a
  # manually-set BACKEND_PORT) would otherwise get silently wiped every rerun.
  cat > frontend/.env.local << EOF
VITE_API_KEY=${BOOTSTRAP_API_KEY}
VITE_ADMIN_KEY=${BOOTSTRAP_ADMIN_KEY}
BACKEND_PORT=${PORT:-8000}
EOF
  echo -e "${GREEN}  ✓  Wired the local API key into frontend/.env.local${RESET}"
else
  echo -e "${YELLOW}  ⚠  Backend didn't report a bootstrap key in time - the dashboard may need one set manually.${RESET}"
fi

# ── Frontend ──────────────────────────────────────────────────────────────────
echo -e "${CYAN}[4/4] Installing frontend dependencies...${RESET}"
cd frontend
npm install -q 2>/dev/null || npm install

echo -e "${GREEN}      Starting dashboard on :5173...${RESET}"
npm run dev &
FRONTEND_PID=$!
cd ..

# ── Ready ─────────────────────────────────────────────────────────────────────
sleep 3

# Same reasoning as the backend check above: confirm both backgrounded
# processes are actually still alive before declaring success.
if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
  echo -e "${RED}  ✗  Backend process is no longer running. Check the output above for what crashed it.${RESET}"
  exit 1
fi
if ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
  echo -e "${RED}  ✗  Frontend process is no longer running. Check the output above for what crashed it.${RESET}"
  kill "$BACKEND_PID" 2>/dev/null
  exit 1
fi

echo ""
echo -e "${GREEN}${BOLD}  AgentShield is running!${RESET}"
echo -e "  ${CYAN}Dashboard:${RESET}  http://localhost:5173"
echo -e "  ${CYAN}API:${RESET}        http://localhost:${PORT:-8000}"
echo -e "  ${CYAN}API Docs:${RESET}   http://localhost:${PORT:-8000}/docs"
echo ""
echo -e "${YELLOW}  Press Ctrl+C to stop both services${RESET}"

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; echo 'Stopped.'" INT TERM
wait
