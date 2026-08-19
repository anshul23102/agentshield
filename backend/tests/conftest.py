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
for _provider_key in ("GITHUB_TOKEN", "GROQ_API_KEY", "OPENROUTER_API_KEY"):
    # Set to "" rather than popping: LLMAnalyzer.__init__() calls
    # load_dotenv() on every construction, which only skips keys already
    # PRESENT in os.environ - a popped key with a real value sitting in a
    # developer's local backend/.env gets silently reloaded right back,
    # quietly turning "pattern-only, no network" tests into ones that make
    # real LLM API calls. An empty string still counts as "present" to
    # load_dotenv (blocking the reload) while still reading as falsy to
    # every `if x_key:` check in the app.
    os.environ[_provider_key] = ""

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from database.db import init_db
from shield.auth import create_api_key
from shield import ThreatDetector
from shield.output_guard import OutputGuard
import main as main_module


@pytest_asyncio.fixture
async def raw_client():
    """An unauthenticated HTTP client wired directly into the ASGI app, no
    network hop. Use this to test the 401/403 paths themselves.

    Route handlers get ThreatDetector/OutputGuard via Depends(get_detector) /
    Depends(get_output_guard), which read them off app.state - normally
    populated by the app's lifespan(). httpx's ASGITransport doesn't run
    lifespan events on its own (that needs a separate tool like
    asgi-lifespan), and spinning up the full lifespan - including the
    WebSocket broadcast worker, demo generator, and retention loop - for
    every single test is unnecessary overhead for what's fast API-level
    testing. Setting app.state directly here is the same seam a production
    lifespan populates, just without the background tasks tests don't need.
    """
    await init_db()
    main_module.app.state.detector = ThreatDetector()
    main_module.app.state.output_guard = OutputGuard()
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
