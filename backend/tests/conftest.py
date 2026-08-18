"""
Test configuration. Env vars here MUST be set before `main` (and therefore
`database.db`) is imported, since both read os.environ at module load time.
"""
import os
import sys
import tempfile
from pathlib import Path

_TMP_DIR = tempfile.mkdtemp(prefix="agentshield_test_")
os.environ["AGENTSHIELD_DB_PATH"] = str(Path(_TMP_DIR) / "test.db")
os.environ["AGENTSHIELD_SEED_DATA"] = "false"        # deterministic: start from an empty DB
os.environ["AGENTSHIELD_DEMO_TRAFFIC"] = "false"      # no background synthetic events during tests
os.environ["AGENTSHIELD_RATE_LIMIT_PER_MINUTE"] = "100000"  # don't let the limiter fail a busy test run
os.environ.pop("GITHUB_TOKEN", None)                  # force pattern-only mode: deterministic, no network
os.environ.pop("GROQ_API_KEY", None)
os.environ.pop("OPENROUTER_API_KEY", None)

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from database.db import init_db
from shield.auth import create_api_key
import main as main_module


@pytest_asyncio.fixture
async def raw_client():
    """An unauthenticated HTTP client wired directly into the ASGI app, no
    network hop. Use this to test the 401/403 paths themselves."""
    await init_db()
    transport = ASGITransport(app=main_module.app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def api_key():
    """A fresh, valid API key for tests that need to authenticate as a tenant."""
    await init_db()
    _key_id, raw_key = await create_api_key("pytest")
    return raw_key


@pytest_asyncio.fixture
async def client(raw_client, api_key):
    """The common case: an HTTP client already carrying a valid API key,
    so existing tests don't all need to thread auth through by hand."""
    raw_client.headers["X-API-Key"] = api_key
    yield raw_client


@pytest_asyncio.fixture
async def admin_headers():
    return {"X-Admin-Key": main_module.ADMIN_KEY}
