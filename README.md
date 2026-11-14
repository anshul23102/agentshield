# AgentShield

Built for Microsoft Build AI 2026 (theme: Security in the Agentic Future). Solo project by Anshul Jain, IIIT Delhi.

AgentShield is a bidirectional security middleware for AI agents. It inspects a prompt before it reaches your agent, scans the agent's reply before it reaches the user, remembers each session so multi-turn attacks can be spotted, and streams every decision to a live dashboard. It is built with production practices (authentication, tenant isolation, rate limits, tests, CI, dependency audits), but it is a prototype: see "Known limitations" for what that means in practice.

## Links

- Live dashboard: https://agentshield-three.vercel.app
- API: https://agentshield-api-658e.onrender.com (docs at `/docs`, status at `/status`)
- Repository: https://github.com/anshul23102/agentshield

The free hosting tier spins the API down when idle, so the first request after a quiet period can take 30 to 60 seconds.

## What it does

1. **Input guard.** Four layers, in the order the code runs them:
   1. **Pattern matching.** 54 compiled signatures in 10 attack categories, run after Unicode normalization (NFKC, look-alike characters, spacing tricks). Instructions hidden in base64 or hex are decoded and re-scanned, and leetspeak such as `Ign0re` is handled.
   2. **Keyword check.** 64 weighted keyword signals in three severity tiers.
   3. **Behavior.** Per-session memory flags a falling trust-score streak, message bursts and oversized inputs, which is how an attack spread over several innocent-looking turns is caught.
   4. **LLM analysis (optional).** If a provider key is configured, a model gives a semantic verdict. Its reply is validated and clamped, and if the provider fails the deterministic layers still decide.
2. **Trust score.** Every request gets a score from 0 to 100 and a verdict: `allow` (above 60), `warn` (31 to 60) or `block` (30 or below). A critical pattern match always blocks.
3. **Output guard.** 23 leak signatures (cloud and API keys, private keys, JWTs, card numbers with a Luhn check, Aadhaar with a Verhoeff check, IBANs with a MOD-97 check, emails, phone numbers validated by libphonenumber, connection strings) are replaced with placeholders.
4. **Live dashboard.** Posture, block rate, trends, recent decisions, a simulator, an interactive pipeline view and a threat library.
5. **Python SDK** that wraps an agent call in a few lines.

## Measured detection quality

The earlier version of this README claimed the pattern layers "catch 90%+ of attacks". That number had never been measured, and when it was measured it was wrong. The evaluation harness lives in `backend/evaluation/` and is reproducible:

```bash
cd backend
python -m evaluation.evaluate                          # curated set, no network needed
python -m evaluation.evaluate_public --split both      # public benchmark, read over HTTPS into memory
python -m evaluation.evaluate --llm --delay 2.5        # include Layer 4 (sends prompts to your provider)
```

Deterministic layers only (layers 1 to 3), warn or block counted as detected:

| Test set | Prompts | Precision | Recall | False positive rate |
|---|---|---|---|---|
| Curated development set, first measurement | 177 (85 attacks) | 0.91 | 0.35 | 0.03 |
| Curated development set, after fixes | 192 (85 attacks) | 0.94 | 0.59 | 0.03 |
| `deepset/prompt-injections`, after fixes (not tuned on it) | 662 (263 attacks) | 1.00 | 0.06 | 0.00 |

With Layer 4 (Groq `openai/gpt-oss-120b`) enabled, warn or block counted as detected:

| Test set | Prompts | Precision | Recall | False positive rate |
|---|---|---|---|---|
| Curated development set, layers 1 to 4 | 192 (85 attacks) | 0.93 | 0.99 | 0.06 |
| `deepset/prompt-injections` test split, layers 1 to 3 | 116 (60 attacks) | 1.00 | 0.02 | 0.00 |
| `deepset/prompt-injections` test split, layers 1 to 4 | 116 (60 attacks) | 0.96 | 0.42 | 0.02 |

The curated LLM figure is optimistic because the set was written by the author. The public result is the honest one: the LLM layer lifts recall from 2% to 42% on a hard, largely German benchmark, at the cost of a little precision. A few provider calls failed per run (shown in the evaluator's failure counters) and fell back to the deterministic layers.

How to read this honestly:

- The signature layers are a **fast, precise filter for known attack shapes**, not a general detector. Recall is 100% on textbook styles (direct override, prompt extraction, authority spoofing) and 0% on paraphrased, non-English and plain-language harmful requests. Those need the LLM layer.
- The curated set was written by the author, so it is a regression and development set, not an independent benchmark. The public set is the independent check, and it is deliberately hard (much of it is German and non-textbook phrasing).
- Latency, measured on a laptop with short prompts and the LLM layer off: pattern layer about 0.09 ms, keyword check 0.03 ms, session layer 0.002 ms, full pipeline p50 0.18 ms and p99 0.33 ms.

## How the pipeline is wired

```text
Browser dashboard  <--REST + WebSocket-->  FastAPI backend
                                              |
        prompt -> L1 patterns -> L2 keywords -> L3 session behavior -> L4 LLM (optional) -> trust score
        reply  -> output guard (leak signatures, checksums, redaction)
                                              |
                              SQLite (WAL, pooled), optional Redis
```

- **Storage:** SQLite through a small `aiosqlite` pool. Only a 200-character preview of each prompt is stored, and it is redacted first (regex guard plus Microsoft Presidio running spaCy `en_core_web_sm`). Request payloads are not stored.
- **State:** sessions, the LLM cache, WebSocket tickets and live broadcasts live in process memory by default. Set `REDIS_URL` and all four move to Redis so several workers agree.
- **Real time:** a browser cannot send headers on a WebSocket handshake, so the dashboard swaps its API key for a 60-second single-use ticket over REST and only the ticket goes in the WebSocket URL.

## Run it locally

```bash
git clone https://github.com/anshul23102/agentshield.git
cd agentshield
chmod +x start.sh && ./start.sh
```

Dashboard on http://localhost:5173, API on http://localhost:8000. On first run the backend mints a bootstrap API key and an admin key, prints them once and saves them under `backend/data/` (gitignored); `start.sh` wires the API key into the frontend. This convenience is development only: with `AGENTSHIELD_ENV=production` nothing generated is ever printed or saved.

Manual setup:

```bash
cd backend && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.lock && python run_server.py      # requirements.lock is what CI and Render install
cd ../frontend && npm install && npm run dev
```

`requirements.lock` pins the whole dependency tree. Regenerate it after editing `requirements.txt` with `uv pip compile requirements.txt -o requirements.lock --python-version 3.11`; CI fails if it drifts and runs `pip-audit` against it (currently no known vulnerabilities).

## Authentication

Every inspect, scan and analytics call needs an `X-API-Key` (or `Authorization: Bearer`). Keys look like `ash_live_...`; only a peppered SHA-256 hash is stored. SHA-256 rather than bcrypt is deliberate: keys are 256-bit random tokens, not human passwords, so a slow hash would only add latency. Admin routes need a separate admin key and run the authorization check before request validation.

```bash
cd backend && python scripts/create_api_key.py "a label for this key"
```

### Public demo mode

A public site cannot ship a real key in its JavaScript. With `AGENTSHIELD_PUBLIC_DEMO=true`, `POST /api/demo/session` mints a private key per visitor: it expires after an hour, is limited to 30 requests a minute, and every visitor is their own tenant, so nobody sees anyone else's prompts. Minting is capped globally, the number of active demo keys is capped, and all demo visitors share one hourly budget of LLM calls so a public demo cannot drain your provider quota. When a visitor's key expires, their events are deleted. See `SECURITY.md`.

## Data and privacy, stated plainly

- With **no provider key**, nothing leaves your server.
- With a **provider key** (GitHub Models, Groq or OpenRouter), every prompt of four or more words is sent to that provider for analysis. Secrets and PII that the regex guard recognizes are masked first (`AGENTSHIELD_LLM_REDACT_BEFORE_SEND`, on by default), but the rest of the prompt text is sent. Use `skip_llm` per request, or leave the key unset, to keep prompts local.
- Stored per event: timestamp, tenant, session id, a 16-character hash of the input, the redacted 200-character preview, the verdict and score, matched pattern ids and timing. No IP address is stored.
- Event retention defaults to 30 days (`AGENTSHIELD_EVENT_RETENTION_DAYS`).
- All secrets live in environment variables and are excluded from git.

## Known limitations

- **Detection is not general.** See the table above. Pattern layers will miss anything phrased in a way they do not know. The LLM layer helps, but a model that judges prompts can itself be attacked; the analyzer fences the text and validates the reply, which reduces but does not remove that risk.
- **The LLM layer fails open.** If the provider is down, the deterministic layers decide alone. Failures are logged and counted in `/api/status` (`llm_stats`).
- **The output guard matches text as written.** An agent that base64-encodes or zero-width-splits a secret before replying is not caught.
- **Free hosting is ephemeral.** On Render's free plan the filesystem is wiped on every restart, so the database, API keys and demo sessions reset. A persistent disk needs a paid plan.
- **SQLite serializes writes.** The pool helps connection reuse and reads, not write throughput. The migration path is Postgres.
- **Session state under Redis is last-write-wins.** Two simultaneous requests in one session can lose an update; a Lua script or `WATCH`/`MULTI` would fix it.
- **Docker files are untested.** `docker-compose.yml` was written without a Docker daemon to run it.
- **Per-IP limits need a known proxy count.** Demo minting is limited globally; the per-IP limit only activates when `AGENTSHIELD_TRUSTED_PROXY_COUNT` is set.

## API

```text
GET  /api/status, /api/patterns, /api/output/patterns, /healthz   no auth
POST /api/demo/session                    only when AGENTSHIELD_PUBLIC_DEMO=true
POST /api/inspect, /api/inspect/batch     X-API-Key
POST /api/scan/output                     X-API-Key
GET  /api/analytics, /api/events/recent   X-API-Key (your own data only)
POST /api/ws-ticket                       X-API-Key, then WS /ws/live?ticket=...
     /api/admin/*                         X-Admin-Key
```

## SDK

```python
from agentshield_sdk import AgentShield

shield = AgentShield(api_key="ash_live_...")          # fail_open=False by default

result = shield.inspect(user_input)
response = agent.run(user_input) if result.is_safe else f"Blocked: {result.reasoning}"
safe_response = shield.scan_output(response).redacted_text
```

By default an outage raises an exception so an agent never runs on an uninspected prompt by accident. `fail_open=True` returns an `allow` flagged `degraded=True` instead: more available, but attacks pass during an outage.

## Tests and CI

312 backend tests and 16 SDK tests; backend coverage including `main.py` is 88%. They include a ReDoS suite that fuzzes every detection pattern, tenant-isolation tests on the live WebSocket route, and regression tests for each bug found in the audits. CI runs the tests, a lockfile freshness check, `pip-audit`, `npm audit` and the frontend build.

## Stack

React 18, Vite, Tailwind, Framer Motion, Recharts; Python 3.11, FastAPI, Uvicorn, aiosqlite, Pydantic, Presidio and spaCy, phonenumbers, confusable-homoglyphs, `limits` and Redis (optional); Vercel for the frontend and Render for the API.

## Development disclosure

AI tools were used while building this: GitHub Copilot, OpenAI Codex and Claude. They helped with code suggestions, debugging, refactoring, documentation and deployment troubleshooting. Product scope, the threat model, testing and final review were done by the author, and the measurements above were run rather than assumed.

## License and contact

MIT, see [LICENSE](LICENSE). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
