import asyncio
import base64
import hashlib
import json
import os
import uuid

import pytest
import requests
import websockets

CREATE_URL = "http://127.0.0.1:8080/create"
API_URL = "http://127.0.0.1:8080/api"
AUTH_URL = "http://127.0.0.1:8080/auth"
MESSAGES_URL = "http://127.0.0.1:8080/messages"
CONNECT_URL = "http://127.0.0.1:8080/connect"
JOIN_URL = "http://127.0.0.1:8080/join"
FILES_URL = "http://127.0.0.1:8080/files"
FILE_URL = "http://127.0.0.1:8080/file"
WS_URL = "ws://127.0.0.1:8080/ws"


def uid_hash():
    digest = hashlib.sha256(uuid.uuid4().hex.encode()).digest()
    return base64.b64encode(digest).decode()


def auth_headers(cookie):
    return {"Cookie": cookie} if cookie else {}


@pytest.fixture()
def make_room():
    def make(expire="1", max_messages=None, max_users=None):
        create_data = {"expire": expire}
        if max_messages is not None:
            create_data["max_messages"] = str(max_messages)
        if max_users is not None:
            create_data["max_users"] = str(max_users)
        created = requests.post(CREATE_URL, data=create_data)
        assert created.status_code == 200
        room_id = created.json()["room_id"]
        key_hash = base64.b64encode(b"a" * 32).decode()
        stored = requests.post(API_URL, data={
            "room_id": room_id,
            "room_key": "dGVzdGtleQ==",
            "IV": "dGVzdGl2",
            "key_hash": key_hash,
        })
        assert stored.status_code == 204
        authed = requests.post(AUTH_URL, data={"room_id": room_id, "key_hash": key_hash})
        assert authed.status_code == 204
        cookie = authed.headers["Set-Cookie"].split(";")[0]
        return room_id, cookie

    return make


def test_connect_returns_settings(make_room):
    room_id, _ = make_room(max_messages=10, max_users=5)
    response = requests.post(CONNECT_URL, data={"room_id": room_id})
    assert response.status_code == 200
    settings = response.json()["settings"]
    assert settings["max_messages"] == 10
    assert settings["max_users"] == 5
    assert settings["expire_hours"] >= 1


def test_messages_require_session(make_room):
    room_id, _ = make_room()
    posted = requests.post(MESSAGES_URL, data={"room_id": room_id, "ciphertext": "dGVzdA==", "iv": "dGVzdA=="})
    listed = requests.get(MESSAGES_URL, params={"room_id": room_id, "after_id": 0})
    assert posted.status_code == 401
    assert listed.status_code == 401


def test_message_limit(make_room):
    room_id, cookie = make_room(max_messages=1)
    first = requests.post(MESSAGES_URL, data={"room_id": room_id, "ciphertext": "dGVzdA==", "iv": "dGVzdA=="},
                          headers=auth_headers(cookie))
    second = requests.post(MESSAGES_URL, data={"room_id": room_id, "ciphertext": "dGVzdA==", "iv": "dGVzdA=="},
                           headers=auth_headers(cookie))
    assert first.status_code == 200
    assert second.status_code == 403
    listed = requests.get(MESSAGES_URL, params={"room_id": room_id, "after_id": 0}, headers=auth_headers(cookie))
    assert listed.status_code == 200
    assert len(listed.json()) == 1


def test_ws_rejects_without_cookie(make_room):
    room_id, _ = make_room()

    async def scenario():
        with pytest.raises(websockets.InvalidHandshake):
            async with websockets.connect(f"{WS_URL}?room_id={room_id}"):
                pass

    asyncio.run(scenario())


def test_ws_message_push(make_room):
    room_id, cookie = make_room()

    async def scenario():
        async with websockets.connect(f"{WS_URL}?room_id={room_id}",
                                      additional_headers={"Cookie": cookie}) as ws:
            response = requests.post(MESSAGES_URL, data={"room_id": room_id, "ciphertext": "dGVzdA==",
                                                         "iv": "dGVzdA=="}, headers=auth_headers(cookie))
            assert response.status_code == 200
            frame = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert frame["type"] == "message"
            assert base64.b64decode(frame["ciphertext"]) == b"test"

    asyncio.run(scenario())


def test_join_slots_and_resurrect(make_room):
    room_id, cookie = make_room(max_users=2)
    uid_a = uid_hash()
    first = requests.post(JOIN_URL, data={"room_id": room_id, "uid_hash": uid_a, "nick": "vasya"},
                          headers=auth_headers(cookie))
    assert first.status_code == 200
    assert first.json()["nick"] == "vasya"

    second = requests.post(JOIN_URL, data={"room_id": room_id, "uid_hash": uid_hash(), "nick": ""},
                           headers=auth_headers(cookie))
    assert second.status_code == 200
    assert second.json()["nick"] == "user2"

    third = requests.post(JOIN_URL, data={"room_id": room_id, "uid_hash": uid_hash(), "nick": ""},
                          headers=auth_headers(cookie))
    assert third.status_code == 403

    rejoined = requests.post(JOIN_URL, data={"room_id": room_id, "uid_hash": uid_a, "nick": ""},
                             headers=auth_headers(cookie))
    assert rejoined.status_code == 200
    assert rejoined.json()["nick"] == "vasya"

    connect = requests.post(CONNECT_URL, data={"room_id": room_id})
    assert connect.status_code == 403


def test_ws_presence_frame(make_room):
    room_id, cookie = make_room()

    async def scenario():
        async with websockets.connect(f"{WS_URL}?room_id={room_id}",
                                      additional_headers={"Cookie": cookie}) as ws:
            joined = requests.post(JOIN_URL, data={"room_id": room_id, "uid_hash": uid_hash(), "nick": "ghost"},
                                   headers=auth_headers(cookie))
            assert joined.status_code == 200
            frame = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            assert frame["type"] == "presence"
            assert any(member["nick"] == "ghost" for member in frame["members"])

    asyncio.run(scenario())


def test_files_roundtrip(make_room):
    room_id, cookie = make_room()
    payload = os.urandom(2048)
    params = {
        "room_id": room_id,
        "iv": base64.b64encode(b"x" * 12).decode(),
        "hiv": base64.b64encode(b"y" * 12).decode(),
        "header": base64.b64encode(b'{"v":2,"name":"test.bin"}').decode(),
    }
    upload = requests.post(FILES_URL, params=params, data=payload,
                           headers={"Cookie": cookie, "Content-Type": "application/octet-stream"})
    assert upload.status_code == 200
    file_id = upload.json()["id"]

    unauth = requests.post(FILES_URL, params=params, data=payload,
                           headers={"Content-Type": "application/octet-stream"})
    assert unauth.status_code == 401

    listed = requests.get(FILES_URL, params={"room_id": room_id, "after_id": 0}, headers=auth_headers(cookie))
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [file_id]

    downloaded = requests.get(FILE_URL, params={"id": file_id}, headers=auth_headers(cookie))
    assert downloaded.status_code == 200
    assert downloaded.headers["Content-Type"] == "application/octet-stream"
    assert downloaded.content == payload
