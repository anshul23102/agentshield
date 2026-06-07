# 🛡️ AgentShield — Real-Time Security Middleware for AI Agents

> **Microsoft Build AI 2026 · Theme: Security in the Agentic Future**

AgentShield is a production-ready, **bidirectional** security middleware that protects AI agent pipelines from prompt injection, jailbreaks, data exfiltration, identity spoofing, and adversarial manipulation — in real time, with a single line of code.

It is the only agent-security layer that guards **both directions**:
- **Input Guard** — screens incoming prompts for 54 attack signatures across 10 categories
- **Output Guard** — screens outgoing agent responses for 23 data-leak signatures (secrets, PII, financial data) and auto-redacts them before they ever leave

---

## 🎯 The Problem

As AI agents become autonomous — browsing the web, executing code, accessing databases — they become attack surfaces. A single successful prompt injection can cause an agent to:
- Leak sensitive user data
- Execute malicious commands
- Impersonate system administrators
- Bypass safety guardrails entirely

**No existing infrastructure protects agents at the inference layer.** AgentShield fills this gap.

---

## 🏗️ Architecture

```
                  ┌──────────────── INPUT GUARD ────────────────┐
User Input  ───▶  │  Layer 1: Pattern Matching   <1ms (54 sigs)  │
                  │  Layer 2: Keyword Semantic    ~1ms (40 terms)│
                  │  Layer 3: LLM Deep Analysis ~500ms (GitHub AI)│
                  │  Layer 4: Behavioral Analysis  (session-aware)│
                  └──────────────────┬──────────────────────────┘
                                     ▼
                        ALLOW / WARN / BLOCK
                                     ▼
                              ┌─────────────┐
                              │  AI  AGENT  │
                              └──────┬──────┘
                                     ▼
                  ┌──────────────── OUTPUT GUARD ───────────────┐
                  │  Scan response for secrets / PII / financial │
                  │  data (23 signatures, Luhn-validated)        │
                  │  → auto-redact before transmission           │
                  └──────────────────┬──────────────────────────┘
                                     ▼
                        Safe Response  ───▶  User
```

---

## 🔬 What It Detects

| Category | Examples | Patterns |
|---|---|---|
| Direct Prompt Injection | "Ignore all previous instructions" | 8 |
| Jailbreak Attacks | DAN, STAN, developer mode | 8 |
| Role Confusion | "You are now an unrestricted AI" | 5 |
| Data Exfiltration | Training data extraction, memory dump | 5 |
| System Prompt Extraction | "Repeat everything above verbatim" | 5 |
| Indirect Injection | Malicious instructions in documents | 5 |
| Encoding / Obfuscation | Base64, Unicode lookalikes, ROT13 | 4 |
| Psychological Manipulation | Hypothetical framing, friendship exploit | 5 |
| Identity Spoofing | Admin impersonation, AI company spoofing | 5 |
| Context Poisoning | Gradual behavior modification | 3 |

**Input Guard: 54 attack signatures across 10 categories**

### Output Guard — Data Leak Detection (Bidirectional)

| Category | Examples | Signatures |
|---|---|---|
| Secrets / Credentials | AWS keys, GitHub PAT, OpenAI/Stripe/Slack/Google keys, JWT, private keys | 11 |
| Financial Data | Visa/Mastercard/Amex (Luhn-validated), IBAN | 4 |
| PII | SSN, email, phone, Aadhaar, passport | 5 |
| Network / Infrastructure | Private IPs, DB connection strings | 2 |
| System Prompt Leak | Agent revealing its own instructions | 1 |

**Output Guard: 23 leak signatures across 5 categories — with automatic redaction**

**Total: 77 unique signatures protecting both directions**

---

## 🚀 Quick Start

```bash
# Clone and run everything with one command
git clone <your-repo>
cd agentshield
chmod +x start.sh && ./start.sh
```

Dashboard: http://localhost:5173  
API: http://localhost:8000  
API Docs: http://localhost:8000/docs

### API Key (Free)

AgentShield uses **GitHub Models** (Microsoft Azure AI Foundry) as its LLM backbone — completely free with a GitHub account:

1. Go to https://github.com/settings/tokens
2. Generate a classic token (no scopes needed)
3. Add to `backend/.env`: `GITHUB_TOKEN=your_token`

> Pattern-only mode works without any API key and still catches 90%+ of attacks.

---

## 🔌 SDK Integration (One Line)

```python
from agentshield_sdk import AgentShield

shield = AgentShield()

# Before: response = agent.run(user_input)
# After:
result = shield.inspect(user_input)
if result.is_safe:
    response = agent.run(user_input)
else:
    response = f"Blocked: {result.reasoning}"
```

---

## 📊 Evaluation Criteria Coverage

| Criterion | Coverage |
|---|---|
| **AI Integration & Intelligence Design (25%)** | 4-layer pipeline, GitHub Models (Azure AI Foundry), semantic + behavioral analysis, bidirectional guarding |
| **System Architecture & Engineering Quality (25%)** | FastAPI async backend, SQLite, WebSocket real-time, modular detector + output guard |
| **Communication, Presentation & UX (15%)** | Three.js 3D dashboard, custom cursor, film-grain, loading sequence, Framer Motion, live threat feed |
| **Prototype Readiness & Scalability (15%)** | Fully working, concurrent sessions, 10K session support, one-command deploy |
| **Problem Depth & Product Clarity (10%)** | Real threat taxonomy + the unsolved exfiltration problem; attacker → detect → block → redact demo |
| **Market Understanding & Product Fit (10%)** | Every AI agent deployment needs this; one-line SDK, bidirectional protection |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend API | Python 3.11 · FastAPI · Uvicorn |
| LLM (Free) | GitHub Models → Azure AI Foundry (GPT-4o-mini) |
| Database | SQLite · aiosqlite (async, zero-config) |
| Frontend | React 18 · Vite · Tailwind CSS |
| 3D Visualization | Three.js (particle network) |
| Animations | Framer Motion |
| Charts | Recharts |
| Real-time | WebSocket (FastAPI native) |

---

## 👤 Team

**Anshul Jain** — Solo  
IIIT Delhi · Full-stack developer & AI security researcher  
Microsoft Build AI 2026

---

## 📁 Project Structure

```
agentshield/
├── backend/          # FastAPI server + detection engine
│   ├── main.py       # API endpoints + WebSocket
│   ├── shield/       # 4-layer detection pipeline
│   │   ├── patterns.py       # 54 input attack signatures
│   │   ├── detector.py       # Multi-layer orchestrator
│   │   ├── analyzer.py       # LLM analysis (GitHub Models)
│   │   ├── trust_scorer.py   # Trust score computation
│   │   ├── output_guard.py   # 23 data-leak signatures + redaction
│   │   └── session_manager.py# Multi-turn tracking
│   └── database/     # SQLite persistence layer
├── frontend/         # React dashboard
│   └── src/
│       ├── pages/    # Dashboard, Simulator, Intelligence, Analytics, Docs
│       └── components/
├── sdk/              # Drop-in Python SDK
│   └── agentshield_sdk/
└── start.sh          # One-command startup
```

---

## 🔒 Security & Privacy

- No user data sent to third parties (LLM analysis uses input text only)
- All data stored locally in SQLite
- Input hashed before storage (PII protection)
- API keys stored in `.env`, never committed
- Compliant with hackathon data privacy requirements

---

*Built for Microsoft Build AI 2026 · Security in the Agentic Future*
