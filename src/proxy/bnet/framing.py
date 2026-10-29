from dataclasses import dataclass

from google.protobuf.message import DecodeError, Message


class FramingError(ValueError):
    pass


@dataclass(frozen=True)
class Frame:
    offset: int
    header: Message
    body: bytes


class FrameBuffer:
    """One ordered direction of a Battle.net stream, starting at its first byte."""

    def __init__(self, header_type: type[Message], max_body_size: int = 16 * 1024 * 1024):
        self._header_type = header_type
        self._max_body_size = max_body_size
        self._buffer = bytearray()
        self._offset = 0

    @property
    def pending_bytes(self) -> int:
        return len(self._buffer)

    def feed(self, data: bytes) -> list[Frame]:
        self._buffer.extend(data)
        frames = []
        consumed = 0
        while len(self._buffer) - consumed >= 2:
            header_size = int.from_bytes(self._buffer[consumed:consumed + 2], "big")
            if header_size == 0:
                raise FramingError(f"Empty header at stream offset {self._offset + consumed}")
            body_start = consumed + 2 + header_size
            if len(self._buffer) < body_start:
                break
            header = self._header_type()
            try:
                header.ParseFromString(bytes(self._buffer[consumed + 2:body_start]))
            except DecodeError as error:
                raise FramingError(f"Invalid header at stream offset {self._offset + consumed}") from error
            if not header.IsInitialized():
                raise FramingError(f"Missing header fields: {header.FindInitializationErrors()}")
            if header.size > self._max_body_size:
                raise FramingError(f"Body size {header.size} exceeds limit {self._max_body_size}")
            end = body_start + header.size
            if len(self._buffer) < end:
                break
            frames.append(Frame(self._offset + consumed, header, bytes(self._buffer[body_start:end])))
            consumed = end
        del self._buffer[:consumed]
        self._offset += consumed
        return frames
