# AgentShield

Microsoft Build AI 2026

Theme: Security in the Agentic Future

AgentShield is a production-ready, bidirectional security middleware that protects AI agent pipelines from prompt injection, jailbreaks, data exfiltration, identity spoofing, and adversarial manipulation in real time, with a single line of code.

It checks incoming prompts before they reach an agent, scans outgoing responses before they leave the system, and gives teams a live dashboard for understanding risk, blocks, warnings, safe traffic, and trust posture.

## Submission Links

Live prototype: https://agentshield-three.vercel.app

Backend service: https://agentshield-api-658e.onrender.com

Backend status: https://agentshield-api-658e.onrender.com/status

Backend docs: https://agentshield-api-658e.onrender.com/docs

GitHub repository: https://github.com/anshul23102/agentshield

Demo video: add YouTube link here

## Microsoft AI Stack

AgentShield uses GitHub Models through Azure AI Foundry for optional model-based threat analysis in Layer 3 of the detection pipeline. GitHub Models provides access to GPT-4o-mini within the free tier.

When a `GITHUB_TOKEN` is configured, AgentShield performs deeper semantic analysis on suspicious prompts. Without the token, the system still catches **90%+ of attacks** using pattern matching alone.

Component details:

- Provider: Microsoft Azure AI Foundry
- Model: GPT-4o-mini
- Tier: Free tier
- Integration: GitHub Models API
- Purpose: Layer 3 semantic threat analysis

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

## Data Privacy and Security

**What Data Is Used:**
- Synthetic demo prompts (no real user data required)
- Request metadata (timestamp, IP hash, decision verdict)
- Event logs (block/warn/allow verdicts, pattern matches)
- Secret-looking values shown in demos are synthetic fixtures only.

**How It Is Stored:**
- Local SQLite database in `backend/data/`
- All sensitive values kept in environment variables (never in version control)
- Input previews truncated to first 100 characters before storage
- Secrets (API keys, tokens, credentials) excluded from all logs

**How It Is Protected:**
- Output Guard redacts detected secrets before transmission
- Request payloads are not persisted
- PII detection and masking on output responses
- No third-party data transmission
- All data isolated locally or in private database
- Request size limits, session retention, bounded concurrency

**Compliance Position:**
- No personal data is required for the demo.
- Synthetic demo prompts are used for judging and testing.
- No confidential employer data or proprietary third-party data is required.
- Public repository secrets are excluded through `.gitignore` and environment variable usage.

## Open Source Credits

This project uses the following open-source libraries:

**Frontend:**
- [React 18](https://react.dev) (MIT)
- [Vite](https://vitejs.dev) (MIT)
- [Tailwind CSS](https://tailwindcss.com) (MIT)
- [Framer Motion](https://www.framer.com/motion/) (MIT)
- [Recharts](https://recharts.org) (Apache 2.0)
- [Three.js](https://threejs.org) (MIT)
- [Lucide Icons](https://lucide.dev) (ISC)
- [Axios](https://axios-http.com) (MIT)
- [React Router](https://reactrouter.com) (MIT)

**Backend:**
- [FastAPI](https://fastapi.tiangolo.com) (MIT)
- [Uvicorn](https://www.uvicorn.org) (BSD)
- [SQLite](https://www.sqlite.org) (Public Domain)
- [aiosqlite](https://github.com/omnilib/aiosqlite) (MIT)
- [Pydantic](https://docs.pydantic.dev) (MIT)
- [Python-dotenv](https://github.com/theskumar/python-dotenv) (BSD)

**Deployment:**
- [Vercel](https://vercel.com) (proprietary)
- [Render](https://render.com) (proprietary)

## Development Disclosure

AI-powered development tools were used during the build process. Assistance was used for code suggestions, debugging, refactoring, documentation drafting, and deployment troubleshooting.

Tools used:

- GitHub Copilot for coding suggestions and editing support.
- OpenAI Codex for implementation support, debugging, documentation, and deployment guidance.

Areas where AI assistance was used:

- Architecture review for the bidirectional guard pipeline.
- Backend implementation support for FastAPI routes, WebSocket streaming, and SQLite event storage.
- Frontend implementation support for React pages, dashboard visualizations, and interaction refinements.
- Detection pattern review for input attacks and output leak signatures.
- README drafting and submission documentation.
- Render and Vercel deployment troubleshooting.

Human judgment and engineering decisions were applied throughout the project, including product scope, threat model choices, UI direction, deployment decisions, testing, and final review.

All generated or assisted code was reviewed, edited, and integrated specifically for this project. No external project code was copied without attribution.

## Team

Team name: BloodWyrm

Anshul Jain

Solo participant

IIIT Delhi

Full-stack developer and AI security researcher

Microsoft Build AI 2026
