#!/usr/bin/env python3
"""
Issue a new AgentShield API key from the command line.

Usage:
    python scripts/create_api_key.py "label for this key"

The raw key is printed exactly once. Only its hash is stored - if you lose
it, revoke it (via /api/admin/keys/{id}, requires AGENTSHIELD_ADMIN_KEY) and
issue a new one. There is no recovery.
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db import init_db
from shield.auth import create_api_key


async def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "unlabeled"
    await init_db()
    key_id, raw_key = await create_api_key(label)
    print(f"Created API key '{label}'")
    print(f"  id:  {key_id}")
    print(f"  key: {raw_key}")
    print()
    print("Store this key now - it will not be shown again.")


if __name__ == "__main__":
    asyncio.run(main())
