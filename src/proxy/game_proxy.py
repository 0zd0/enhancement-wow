import base64
import json
import logging
from pathlib import Path

from mitmproxy import tcp

from .bnet.schemas import Schemas
from .bnet.session import RpcSession
from .world.world_relay import Transform, WorldRelay


class SessionKeys:
    def __init__(self):
        self.key_data = []
        self.sessions = []

    def add_data(self, data: bytes):
        if len(data) != 64:
            raise ValueError("Expected 64-byte game key data")
        if data not in self.key_data:
            self.key_data.append(data)
            logging.info("WoW realm join secrets captured")

    def add_session(self, session: bytes):
        if session not in self.sessions:
            self.sessions.append(session)


class AuthTracker:
    def __init__(self, schemas: Schemas, keys: SessionKeys):
        self.rpc = RpcSession(schemas)
        self.keys = keys
        self.pending_tickets = {}
        self.tickets = {}
        self.pending_joins = {}

    def feed(self, client: bool, data: bytes):
        for packet in self.rpc.feed(client, data):
            body = packet.get("body", {})
            attrs = (
                body.get("attribute", [])
                + body.get("result", [])
            )
            blobs = {
                item["name"]: base64.b64decode(
                    item["value"]["blob_value"],
                    validate=True,
                )
                for item in attrs
                if "blob_value" in item.get("value", {})
            }
            token = packet["header"].get("token", 0)

            if client:
                if "Param_ClientInfo" in blobs:
                    raw = blobs["Param_ClientInfo"].rstrip(b"\0")
                    info = json.loads(raw.split(b":", 1)[1])
                    secret = bytes(info["info"]["secret"])
                    if len(secret) != 32:
                        raise ValueError("Invalid client secret")
                    self.pending_tickets[token] = secret

                if any(
                    item["name"].startswith(
                        "Command_RealmJoinRequest_"
                    )
                    for item in attrs
                ):
                    ticket = blobs.get("Param_RealmListTicket")
                    if ticket not in self.tickets:
                        raise ValueError(
                            "Realm join refers to an unknown ticket"
                        )
                    self.pending_joins[token] = self.tickets[ticket]

            else:
                if "Param_RealmListTicket" in blobs:
                    secret = self.pending_tickets.pop(token)
                    self.tickets[
                        blobs["Param_RealmListTicket"]
                    ] = secret

                if "Param_JoinSecret" in blobs:
                    server = blobs["Param_JoinSecret"]
                    if len(server) != 32:
                        raise ValueError("Invalid server secret")
                    client_secret = self.pending_joins.pop(token)
                    self.keys.add_data(client_secret + server)


class GameProxy:
    def __init__(self, transform: Transform):
        self.transform = transform
        self.keys = SessionKeys()
        self.schemas = Schemas(
            Path(__file__).parent / "bnet/bnet.protoset"
        )
        self.auth = {}
        self.world = {}

    def tcp_start(self, flow: tcp.TCPFlow):
        if flow.server_conn.address is None:
            return

        port = flow.server_conn.address[1]
        if port == 1119:
            self.auth[flow.id] = AuthTracker(
                self.schemas, self.keys
            )
        elif port == 3724:
            self.world[flow.id] = WorldRelay(
                flow.id, self.keys, self.transform
            )

    def tcp_message(self, flow: tcp.TCPFlow):
        message = flow.messages[-1]
        try:
            if flow.id in self.auth:
                self.auth[flow.id].feed(
                    message.from_client, message.content
                )
            elif flow.id in self.world:
                message.content = self.world[flow.id].feed(
                    message.from_client, message.content
                )
        except Exception as error:
            # Продолжать поток после ошибки callback/криптографии нельзя.
            logging.error(
                "WoW proxy stopped connection %s: %s",
                flow.id,
                error,
            )
            flow.kill()

    def tcp_end(self, flow: tcp.TCPFlow):
        self.auth.pop(flow.id, None)
        self.world.pop(flow.id, None)

    def tcp_error(self, flow: tcp.TCPFlow):
        self.tcp_end(flow)
