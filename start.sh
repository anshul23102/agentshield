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
echo -e "${CYAN}[1/3] Installing Python dependencies...${RESET}"
cd backend
python3 -m pip install -r requirements.txt -q

if [ ! -f ".env" ]; then
  cp .env.example .env
  echo -e "${YELLOW}  ⚠  Created backend/.env from template."
  echo -e "     Add your GITHUB_TOKEN for LLM analysis (optional).${RESET}"
fi
source .env 2>/dev/null || true

echo -e "${GREEN}[2/3] Starting AgentShield API on :8000...${RESET}"
python3 run_server.py &
BACKEND_PID=$!
cd ..

# ── Frontend ──────────────────────────────────────────────────────────────────
echo -e "${CYAN}[3/3] Installing frontend dependencies...${RESET}"
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
