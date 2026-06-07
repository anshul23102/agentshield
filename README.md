# AgentShield

AgentShield is real-time security middleware for autonomous agent pipelines. It protects prompts before they reach the agent and scans responses before they leave the system.

## What It Does

- Input Guard screens incoming prompts for injection, jailbreak, spoofing, exfiltration, and context poisoning attempts.
- Output Guard scans outgoing responses for secrets, credentials, PII, financial data, network details, and prompt leaks.
- Session tracking watches multi-turn behavior for escalating risk.
- Analytics and WebSocket events power a live security dashboard.
- The Python SDK wraps existing agent calls with a small client.

## Architecture

User input flows through pattern matching, semantic keyword checks, optional LLM analysis, and session-aware scoring. The resulting action is allow, warn, or block. Agent output then passes through the leak scanner, which can redact sensitive content before delivery.

## Quick Start

```bash
git clone <your-repo>
cd agentshield
chmod +x start.sh
./start.sh
```

Dashboard: http://localhost:5173

API: http://localhost:8000

API Docs: http://localhost:8000/docs

## Optional Model Provider

AgentShield can use GitHub Models through Azure Foundry for deeper LLM analysis. Pattern-only mode works without a token.

1. Open https://github.com/settings/tokens
2. Generate a classic token with no scopes
3. Add `GITHUB_TOKEN=your_token` to `backend/.env`

## SDK Integration

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

## Tech Stack

Backend: Python, FastAPI, Uvicorn

Model layer: GitHub Models, Groq, or OpenRouter when configured

Database: SQLite with aiosqlite

Frontend: React, Vite, Tailwind CSS

Visualization: Three.js, Framer Motion, Recharts

Realtime: FastAPI WebSocket

## Project Structure

```text
agentshield/
  backend/
    main.py
    shield/
    database/
  frontend/
    src/
      pages/
      components/
  sdk/
    agentshield_sdk/
  start.sh
```

## Security Notes

- Input previews are hashed and truncated before storage.
- API keys live in `.env` and are excluded from version control.
- Local SQLite persistence keeps the prototype simple.
- Request size limits, session retention, bounded LLM concurrency, and cache limits are configurable.

Built for agent security research and prototype evaluation.
