# AgentShield

AgentShield is a real-time security layer for autonomous agent pipelines. It checks incoming prompts before they reach an agent, scans outgoing responses before they leave the system, and gives teams a live dashboard for understanding risk, blocks, warnings, safe traffic, and trust posture.

## Submission Links

Live prototype: https://agentshield-three.vercel.app

Backend service: https://agentshield-api-658e.onrender.com

Backend status: https://agentshield-api-658e.onrender.com/status

Backend docs: https://agentshield-api-658e.onrender.com/docs

GitHub repository: https://github.com/anshul23102/agentshield

Demo video: add YouTube link here

## Problem

Autonomous agent systems can receive hostile prompts, leak sensitive outputs, and carry risk across multi-turn sessions. A single request can attempt prompt injection, credential exfiltration, spoofing, jailbreak behavior, or context poisoning. A single response can expose secrets, financial data, network details, or private user information.

AgentShield solves this by adding a guard layer around agent calls. It does not replace the agent. It wraps the agent with input inspection, output scanning, session memory, trust scoring, and live telemetry.

## What It Does

- Input Guard screens incoming prompts for injection, jailbreak, spoofing, exfiltration, and context poisoning attempts.
- Output Guard scans outgoing responses for secrets, credentials, PII, financial data, network details, and prompt leaks.
- Session tracking watches multi-turn behavior for escalating risk.
- Trust scoring turns every request into a simple allow, warn, or block decision.
- Live dashboard presents inspected traffic, block rate, detection rate, trust score, recent decisions, and traffic trends.
- Simulator lets judges test risky and safe prompts without needing an external agent.
- Python SDK shows how AgentShield can wrap existing agent calls with a small client.

## How It Works

1. A user prompt enters the Input Guard.
2. Pattern signatures and semantic checks detect known attack behavior.
3. Optional model analysis can add deeper review when a provider token is configured.
4. Session memory adjusts risk when suspicious behavior builds over time.
5. The trust scorer returns `allow`, `warn`, or `block`.
6. Safe or warned prompts can continue to the agent.
7. Agent responses pass through the Output Guard.
8. Sensitive content is detected and redacted before the response leaves the system.
9. Events stream to the dashboard through WebSocket updates.

## Live Prototype Guide

Open the live prototype:

```text
https://agentshield-three.vercel.app
```

Recommended judging flow:

1. Open Dashboard to see live posture, metrics, trends, and recent decisions.
2. Open Simulator and run a safe prompt.
3. Run a risky prompt such as credential exfiltration or prompt override.
4. Return to Dashboard and watch the decision stream update.
5. Open Output Guard and test a response that contains secrets or sensitive data.
6. Open Docs for endpoint references and SDK examples.

## Architecture

```text
Browser dashboard
  |
  | REST and WebSocket
  v
FastAPI backend
  |
  | Input Guard
  | Pattern signatures
  | Optional model review
  | Session memory
  | Trust scorer
  | Output Guard
  v
SQLite event store and live telemetry
```

## Tech Stack

Frontend: React, Vite, Tailwind CSS, Framer Motion, Recharts, Three.js

Backend: Python, FastAPI, Uvicorn, SQLite, aiosqlite

Realtime: FastAPI WebSocket

Deployment: Vercel for frontend, Render for backend

SDK: Python client wrapper

## Local Setup

Clone the repository:

```bash
git clone https://github.com/anshul23102/agentshield.git
cd agentshield
```

Run the full local stack:

```bash
chmod +x start.sh
./start.sh
```

Local URLs:

```text
Dashboard: http://localhost:5173
Backend: http://localhost:8000
Backend docs: http://localhost:8000/docs
```

## Backend Setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run_server.py
```

Optional environment variables:

```text
GITHUB_TOKEN=your_token
GROQ_API_KEY=your_token
OPENROUTER_API_KEY=your_token
```

AgentShield still works without provider tokens by using the local pattern database.

## Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

For deployed frontend builds, set:

```text
VITE_API_URL=https://agentshield-api-658e.onrender.com
```

## API Highlights

```text
GET  /api/status
GET  /api/analytics
GET  /api/events/recent
POST /api/inspect
POST /api/inspect/batch
POST /api/scan/output
GET  /api/patterns
GET  /api/output/patterns
WS   /ws/live
```

## SDK Example

```python
from agentshield_sdk import AgentShield

shield = AgentShield()

result = shield.inspect(user_input)
if result.is_safe:
    response = agent.run(user_input)
else:
    response = f"Blocked: {result.reasoning}"

scan = shield.scan_output(response)
safe_response = scan.redacted_text
```

## Project Structure

```text
agentshield/
  backend/
    main.py
    run_server.py
    database/
    shield/
  frontend/
    src/
      components/
      hooks/
      pages/
      utils/
  sdk/
    agentshield_sdk/
  render.yaml
  start.sh
```

## Deployment Notes

Render backend:

```text
Root directory: backend
Build command: pip install -r requirements.txt
Start command: python run_server.py
Python version: 3.11.11
```

Vercel frontend:

```text
Root directory: frontend
Framework: Vite
Build command: npm run build
Output directory: dist
Environment variable: VITE_API_URL=https://agentshield-api-658e.onrender.com
```

## Security Notes

- Input previews are truncated before storage.
- Secret values are kept in environment variables and excluded from version control.
- Output Guard redacts detected secrets before delivery.
- Request size limits, session retention, bounded model concurrency, and cache limits are configurable.
- Local SQLite persistence keeps the prototype simple and easy to inspect.

## Team

Anshul Jain
