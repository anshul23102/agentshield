# agentshield-sdk

Python client for [AgentShield](https://github.com/anshul23102/agentshield) — wrap any agent call with input/output security inspection in one line.

## Install

```bash
pip install -e ./sdk        # from the repo root, editable install for local dev
```

or, once published:

```bash
pip install agentshield-sdk
```

## Usage

The server requires an API key on every inspect/scan/analytics call. Issue one
on the server with `python scripts/create_api_key.py "label"` (requires
`AGENTSHIELD_ADMIN_KEY`), then pass it to the client or set `AGENTSHIELD_API_KEY`.

```python
from agentshield_sdk import AgentShield

shield = AgentShield(base_url="http://localhost:8000", api_key="ash_live_...")

result = shield.inspect(user_input)
if result.is_safe:
    response = agent.run(user_input)
else:
    response = f"Blocked: {result.reasoning}"

scan = shield.scan_output(response)
safe_response = scan.redacted_text
```

See `examples/basic_usage.py` for multi-turn session tracking and batch inspection.
