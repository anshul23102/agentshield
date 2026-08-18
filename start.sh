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

echo -e "${GREEN}[2/4] Starting AgentShield API on :8000...${RESET}"
python3 run_server.py &
BACKEND_PID=$!
cd ..

# ── API key bootstrap ─────────────────────────────────────────────────────────
# The backend mints its own API key + admin key on first startup and writes
# them to backend/data/. Wait for that write, then wire them into the
# frontend automatically - no manual copy-pasting for a fresh clone.
echo -e "${CYAN}[3/4] Waiting for the backend to issue local API keys...${RESET}"
for i in $(seq 1 30); do
  if [ -f "backend/data/.bootstrap_api_key" ] && [ -f "backend/data/.admin_key" ]; then
    break
  fi
  sleep 0.5
done

if [ -f "backend/data/.bootstrap_api_key" ]; then
  BOOTSTRAP_API_KEY=$(cat backend/data/.bootstrap_api_key)
  BOOTSTRAP_ADMIN_KEY=$(cat backend/data/.admin_key 2>/dev/null || echo "")
  cat > frontend/.env.local << EOF
VITE_API_KEY=${BOOTSTRAP_API_KEY}
VITE_ADMIN_KEY=${BOOTSTRAP_ADMIN_KEY}
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
echo ""
echo -e "${GREEN}${BOLD}  AgentShield is running!${RESET}"
echo -e "  ${CYAN}Dashboard:${RESET}  http://localhost:5173"
echo -e "  ${CYAN}API:${RESET}        http://localhost:8000"
echo -e "  ${CYAN}API Docs:${RESET}   http://localhost:8000/docs"
echo ""
echo -e "${YELLOW}  Press Ctrl+C to stop both services${RESET}"

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; echo 'Stopped.'" INT TERM
wait
