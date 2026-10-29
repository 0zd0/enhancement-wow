from google.protobuf.message import DecodeError

from .framing import Frame, FrameBuffer
from .schemas import Method, Schemas


class RpcSession:
    """Two directional frame buffers and request tokens for one TCP connection."""

    def __init__(self, schemas: Schemas):
        self.schemas = schemas
        self._buffers = {direction: FrameBuffer(schemas.header_type) for direction in (True, False)}
        self._pending: dict[tuple[bool, int], Method | None] = {}

    def pending_bytes(self, from_client: bool) -> int:
        return self._buffers[from_client].pending_bytes

    def feed(self, from_client: bool, data: bytes) -> list[dict]:
        return [self._decode(from_client, frame) for frame in self._buffers[from_client].feed(data)]

    def _decode(self, from_client: bool, frame: Frame) -> dict:
        header = frame.header
        response = header.service_id == 0xFE or header.is_response
        if response:
            method = self._pending.pop((not from_client, header.token), None)
        else:
            method = self.schemas.methods.get((header.service_hash, header.method_id & 0x3FFFFFFF))
            self._pending[(from_client, header.token)] = method
        result = {
            "direction": "client -> server" if from_client else "server -> client",
            "stream_offset": frame.offset,
            "kind": "response" if response else "request",
            "header": self.schemas.to_dict(header),
            "method": method.name if method else None,
            # "body_hex": frame.body.hex(),
        }
        if method is None:
            result["note"] = "Unknown service/method or response without a captured request"
            return result
        if response and header.status and not frame.body:
            return result
        body = (method.response if response else method.request)()
        try:
            body.ParseFromString(frame.body)
            if not body.IsInitialized():
                raise DecodeError(f"Missing fields: {body.FindInitializationErrors()}")
            result["body_type"] = body.DESCRIPTOR.full_name
            result["body"] = self.schemas.to_dict(body)
        except DecodeError as error:
            result["decode_error"] = str(error)
        return result
