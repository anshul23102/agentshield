"""End-to-end tests for the live feed (/ws/live) and the ticket handshake behind it.

A browser cannot attach a header to a WebSocket handshake, so the dashboard swaps
its API key for a short-lived single-use ticket over REST and puts only the
ticket in the WebSocket URL. These tests drive the real route through
Starlette's TestClient, including the broadcast worker, so the properties that
matter are proven on the actual endpoint and not just on helper functions."""
import asyncio

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import main as main_module
from shield.auth import create_api_key


@pytest.fixture
def app_client(monkeypatch, tmp_path):
    # Entering TestClient runs the app's lifespan (broadcast worker included).
    # Keep it from touching the developer's real local bootstrap-key file.
    monkeypatch.setenv("AGENTSHIELD_AUTO_BOOTSTRAP_KEY", "false")
    monkeypatch.setattr(main_module, "DATA_DIR", tmp_path)
    with TestClient(main_module.app) as client:
        yield client


def new_key(label):
    return asyncio.new_event_loop().run_until_complete(create_api_key(label))[1]


def ticket_for(client, key):
    resp = client.post("/api/ws-ticket", headers={"X-API-Key": key})
    assert resp.status_code == 200
    return resp.json()["ticket"]


def test_a_connection_without_a_ticket_is_refused(app_client):
    with pytest.raises(WebSocketDisconnect) as exc:
        with app_client.websocket_connect("/ws/live"):
            pass
    assert exc.value.code == 4401


def test_a_forged_ticket_is_refused(app_client):
    with pytest.raises(WebSocketDisconnect) as exc:
        with app_client.websocket_connect("/ws/live?ticket=not-a-real-ticket"):
            pass
    assert exc.value.code == 4401


def test_a_ticket_can_only_be_used_once(app_client):
    key = new_key("ws-single-use")
    ticket = ticket_for(app_client, key)
    with app_client.websocket_connect(f"/ws/live?ticket={ticket}") as ws:
        assert ws.receive_json()["type"] == "init"
    with pytest.raises(WebSocketDisconnect) as exc:   # replaying the same ticket
        with app_client.websocket_connect(f"/ws/live?ticket={ticket}"):
            pass
    assert exc.value.code == 4401


def test_minting_a_ticket_needs_a_valid_api_key(app_client):
    assert app_client.post("/api/ws-ticket").status_code == 401
    assert app_client.post("/api/ws-ticket", headers={"X-API-Key": "ash_live_nope"}).status_code == 401


def test_live_events_reach_only_the_tenant_that_caused_them(app_client):
    alice_key, bob_key = new_key("ws-alice"), new_key("ws-bob")
    with app_client.websocket_connect(f"/ws/live?ticket={ticket_for(app_client, alice_key)}") as alice, \
         app_client.websocket_connect(f"/ws/live?ticket={ticket_for(app_client, bob_key)}") as bob:
        assert alice.receive_json()["type"] == "init"
        assert bob.receive_json()["type"] == "init"

        app_client.post("/api/inspect", json={"text": "alice-only private question about payroll"},
                        headers={"X-API-Key": alice_key})
        alices_event = alice.receive_json()
        assert alices_event["type"] == "threat_event"
        assert "payroll" in alices_event["input_preview"]

        # Bob's next message must be HIS OWN event, proving Alice's never arrived.
        app_client.post("/api/inspect", json={"text": "bob-only question about holidays"},
                        headers={"X-API-Key": bob_key})
        bobs_event = bob.receive_json()
        assert bobs_event["type"] == "threat_event"
        assert "holidays" in bobs_event["input_preview"]
        assert "payroll" not in str(bobs_event)


def test_the_init_message_only_contains_the_connecting_tenants_history(app_client):
    key = new_key("ws-history")
    app_client.post("/api/inspect", json={"text": "history entry that belongs to this tenant only"},
                    headers={"X-API-Key": key})
    other = new_key("ws-history-other")
    with app_client.websocket_connect(f"/ws/live?ticket={ticket_for(app_client, other)}") as ws:
        init = ws.receive_json()
    assert init["type"] == "init"
    assert all("belongs to this tenant" not in e["input_preview"] for e in init["recent_events"])


def test_one_tenant_cannot_exceed_its_connection_cap(app_client, monkeypatch):
    monkeypatch.setattr(main_module, "MAX_WS_CLIENTS_PER_TENANT", 1)
    key = new_key("ws-cap")
    with app_client.websocket_connect(f"/ws/live?ticket={ticket_for(app_client, key)}") as first:
        assert first.receive_json()["type"] == "init"
        with pytest.raises(WebSocketDisconnect) as exc:
            with app_client.websocket_connect(f"/ws/live?ticket={ticket_for(app_client, key)}"):
                pass
        assert exc.value.code == 1013
