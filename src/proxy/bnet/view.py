import json
from functools import cached_property
from pathlib import Path

from mitmproxy import contentviews, tcp

from .framing import FramingError
from .schemas import Schemas
from .session import RpcSession


class BattleNetContentview(contentviews.Contentview):
    name = "Battle.net RPC"
    syntax_highlight = "yaml"

    @cached_property
    def schemas(self) -> Schemas:
        return Schemas(Path(__file__).with_name("bnet.protoset"))

    def render_priority(self, data: bytes, metadata: contentviews.Metadata) -> float:
        flow = metadata.flow
        if isinstance(flow, tcp.TCPFlow) and flow.server_conn.address:
            if flow.server_conn.address[1] == 1119:
                return 2
        return -1

    def prettify(self, data: bytes, metadata: contentviews.Metadata) -> str:
        flow, selected = metadata.flow, metadata.tcp_message
        if not isinstance(flow, tcp.TCPFlow) or selected is None:
            raise ValueError("Select a TCP message from a Battle.net connection")
        # Replay the prefix to preserve framing/tokens when opening an existing .mitm.
        # No mutable global session state: selecting messages in any order is safe.
        session = RpcSession(self.schemas)
        for message in flow.messages:
            try:
                frames = session.feed(message.from_client, message.content)
            except FramingError as error:
                return json.dumps({
                    "framing_error": str(error),
                    "note": "Requires the stream from its start, after TLS decryption",
                    "selected_chunk_hex": data.hex(),
                }, indent=2)
            if message is selected:
                result = {
                    "frames_completed_in_this_chunk": frames,
                    "pending_bytes_this_direction": session.pending_bytes(message.from_client),
                }
                if not frames:
                    result["note"] = "Frame continues in a later chunk; open that chunk to see it"
                return json.dumps(result, ensure_ascii=False, indent=2)
        raise ValueError("Selected TCP message is absent from the flow")
