import io as bytes_io
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mitmproxy import connection, contentviews, io, tcp
from mitmproxy.contentviews._registry import ContentviewRegistry

from proxy.bnet.framing import FrameBuffer, FramingError
from proxy.bnet.schemas import Schemas
from proxy.bnet.session import RpcSession
from proxy.bnet.view import BattleNetContentview


SCHEMAS = Schemas(Path(__file__).parents[1] / "src/proxy/bnet/bnet.protoset")


def packet(body=b"", *, token=7, response=False, service_hash=0x3FC1274D, method_id=1):
    header = SCHEMAS.header_type(
        service_id=0xFE if response else 0,
        token=token,
        method_id=method_id,
        service_hash=service_hash,
        size=len(body),
    ).SerializeToString()
    return len(header).to_bytes(2, "big") + header + body


def request_body():
    message = SCHEMAS.message_type("bgs.protocol.game_utilities.v1.ClientRequest")()
    attribute = message.attribute.add()
    attribute.name = "Command_RealmListTicketRequest_v1"
    attribute.value.bool_value = True
    return message.SerializeToString()


class DecoderTests(unittest.TestCase):
    def test_every_split_point_and_coalesced_packets(self):
        raw = packet(request_body())
        for split in range(len(raw)):
            buffer = FrameBuffer(SCHEMAS.header_type)
            self.assertEqual(buffer.feed(raw[:split]), [])
            frames = buffer.feed(raw[split:] + raw)
            self.assertEqual([frame.body for frame in frames], [request_body()] * 2)
            self.assertEqual([frame.offset for frame in frames], [0, len(raw)])
            self.assertEqual(buffer.pending_bytes, 0)

    def test_token_direction_and_out_of_order_responses(self):
        session = RpcSession(SCHEMAS)
        # Both peers may independently use the same token.
        session.feed(True, packet(request_body(), token=7))
        session.feed(False, packet(token=7, service_hash=0x5DBB51C2))
        session.feed(True, packet(request_body(), token=8))
        late = session.feed(False, packet(response=True, token=8))[0]
        other_direction = session.feed(True, packet(response=True, token=7))[0]
        original = session.feed(False, packet(response=True, token=7))[0]
        self.assertIn("ClientResponse", late["body_type"])
        self.assertIn("ProcessTaskResponse", other_direction["body_type"])
        self.assertIn("ClientResponse", original["body_type"])

    def test_unknown_method_preserves_body(self):
        decoded = RpcSession(SCHEMAS).feed(True, packet(b"\x01\x02", service_hash=123))[0]
        self.assertIsNone(decoded["method"])
        self.assertEqual(decoded["body_hex"], "0102")

    def test_invalid_header_and_size(self):
        with self.assertRaises(FramingError):
            FrameBuffer(SCHEMAS.header_type).feed(b"\x00\x00")
        with self.assertRaises(FramingError):
            FrameBuffer(SCHEMAS.header_type, max_body_size=1).feed(packet(b"ab"))

    def test_invalid_body_is_not_reported_as_decoded(self):
        decoded = RpcSession(SCHEMAS).feed(True, packet(b"\xff"))[0]
        self.assertIn("decode_error", decoded)
        self.assertNotIn("body", decoded)

    def test_method_ids_come_from_options_not_list_position(self):
        self.assertTrue(SCHEMAS.methods[(0x3FC1274D, 10)].name.endswith("GetAllValuesForAttribute"))

    def test_ui_and_mitm_round_trip_with_partial_interleaved_directions(self):
        flow = tcp.TCPFlow(
            connection.Client(peername=("127.0.0.1", 0), sockname=("127.0.0.1", 0)),
            connection.Server(address=("example.invalid", 1119)),
        )
        raw = packet(request_body())
        flow.messages = [
            tcp.TCPMessage(True, raw[:3]),
            tcp.TCPMessage(False, packet(response=True, token=99)),
            tcp.TCPMessage(True, raw[3:]),
            tcp.TCPMessage(False, packet(response=True)),
        ]
        stream = bytes_io.BytesIO()
        io.FlowWriter(stream).add(flow)
        stream.seek(0)
        restored = next(io.FlowReader(stream).stream())
        original = [message.content for message in restored.messages]
        view = BattleNetContentview()
        registry = ContentviewRegistry()
        registry.register(view)
        with patch("mitmproxy.ctx.options", SimpleNamespace(protobuf_definitions=None), create=True):
            def render(index):
                result = contentviews.prettify_message(restored.messages[index], restored, view.name, registry)
                return json.loads(result.text)
            self.assertIn("ClientResponse", render(3)["frames_completed_in_this_chunk"][0]["body_type"])
            self.assertEqual(render(0)["pending_bytes_this_direction"], 3)
            decoded = render(2)["frames_completed_in_this_chunk"][0]
            self.assertEqual(decoded["body"]["attribute"][0]["name"], "Command_RealmListTicketRequest_v1")
            self.assertIn("ClientResponse", render(3)["frames_completed_in_this_chunk"][0]["body_type"])
            self.assertEqual(original, [message.content for message in restored.messages])


if __name__ == "__main__":
    unittest.main()
