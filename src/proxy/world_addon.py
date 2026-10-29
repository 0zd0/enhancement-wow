import base64
import json
import zlib

from mitmproxy import contentviews, ctx, tcp, flow
from packaging.metadata import Metadata

from proxy.world.world_crypto import derive_encryption
from proxy.world.world_protocol import WorldSession, handshake, session_for


def is_world(flow: flow.Flow | None) -> bool:
    return (
        isinstance(flow, tcp.TCPFlow)
        and flow.server_conn.address is not None
        and flow.server_conn.address[1] == 3724
    )


class WorldContentview(contentviews.Contentview):
    name = "WoW decrypted"
    syntax_highlight = "yaml"

    def __init__(self, owner):
        self.owner = owner

    def render_priority(self, data: bytes, metadata: contentviews.Metadata):
        return 2 if is_world(metadata.flow) else -1

    def prettify(self, data: bytes, metadata: contentviews.Metadata):
        flow, selected = metadata.flow, metadata.tcp_message
        if not is_world(flow) or selected is None:
            raise ValueError("Select a WoW TCP message")

        try:
            client = bytes(json.loads(ctx.options.wow_client_secret))
            server = base64.b64decode(
                ctx.options.wow_server_secret,
                validate=True,
            )
            if len(client) != 32 or len(server) != 32:
                raise ValueError("Expected two 32-byte secrets")

            hello = handshake(flow.messages)
            if hello is None:
                return "Handshake incomplete: need AuthChallenge and AuthSession"

            session_key = session_for(
                hello,
                client + server,
                self.owner.flows.values(),
            )
            decoder = WorldSession(
                derive_encryption(session_key, hello.server, hello.client)
            )

            for message in flow.messages:
                packets = decoder.feed(message.from_client, message.content)
                if message is selected:
                    return json.dumps({
                        "packets_completed_in_this_chunk": packets,
                        "pending_bytes_this_direction": len(
                            decoder.wire.buffers[message.from_client]
                        ),
                    }, indent=2)

            raise ValueError("Selected message is absent from flow")

        except (ValueError, TypeError, zlib.error) as error:
            return json.dumps({"decode_error": str(error)}, indent=2)


class WorldAddon:
    def __init__(self):
        self.flows = {}

    def load(self, loader):
        loader.add_option(
            "wow_client_secret", str, "",
            "ClientInfo info.secret as JSON array",
        )
        loader.add_option(
            "wow_server_secret", str, "",
            "Param_JoinSecret as base64",
        )
        contentviews.add(WorldContentview(self))

    def tcp_start(self, flow):
        if is_world(flow):
            self.flows[flow.id] = flow


addons = [WorldAddon()]
