"""PostgreSQL 17 extended-query message framing.

Implements the framing described in PostgreSQL 17 documentation section
53.7 ("Message Formats"): every message is a one-byte type, a four-byte
big-endian length (covering itself and the payload, excluding the type
byte) followed by the payload.

Only message types belonging to the authenticated, no-COPY extended-query
flow accepted by this project are recognized here; anything else is a
fatal, whole-run protocol violation.
"""

from __future__ import annotations

from dataclasses import dataclass


class ProtocolViolation(Exception):
    """Fatal violation: the whole run is rejected.

    ``direction`` is "client" or "server"; ``offset`` is the zero-based
    byte offset where the offending message starts (or end-of-stream for
    a missing/truncated final message).
    """

    def __init__(self, direction: str, offset: int, reason: str):
        self.direction = direction
        self.offset = offset
        self.reason = reason
        super().__init__(f"{direction} message at byte {offset}: {reason}")


# Client -> server types allowed after authentication (PG17 §53.2.3/4).
CLIENT_TYPES = frozenset("PBDHESFcC")
# Server -> client types allowed as answers to the above.
SERVER_TYPES = frozenset("123CTDEZns")


@dataclass(frozen=True)
class RawMessage:
    type: str
    start: int          # zero-based byte offset of the type byte
    length: int         # declared length field value
    payload: bytes


def frame_stream(data: bytes, direction: str) -> list[RawMessage]:
    """Split one direction's bytes into framed messages.

    Raises ProtocolViolation on truncated frames, length under 4, unknown
    message types or any trailing bytes that do not form a full message.
    """
    allowed = CLIENT_TYPES if direction == "client" else SERVER_TYPES
    messages: list[RawMessage] = []
    pos = 0
    n = len(data)
    while pos < n:
        start = pos
        # Need at least type byte + 4 length bytes.
        if n - pos < 5:
            raise ProtocolViolation(
                direction, start, "truncated message header"
            )
        mtype = chr(data[pos])
        if mtype not in allowed:
            raise ProtocolViolation(
                direction,
                start,
                f"message type {mtype!r} is not allowed in this flow",
            )
        length = int.from_bytes(data[pos + 1 : pos + 5], "big")
        if length < 4:
            raise ProtocolViolation(
                direction, start, f"length field {length} is smaller than 4"
            )
        end = pos + 1 + length
        if end > n:
            raise ProtocolViolation(
                direction,
                start,
                "declared length runs past end of stream (truncated frame)",
            )
        messages.append(
            RawMessage(mtype, start, length, data[pos + 5 : end])
        )
        pos = end
    return messages


class PayloadReader:
    """Sequential reader for a message payload with bounds checking."""

    def __init__(self, payload: bytes, direction: str, start: int):
        self._buf = payload
        self._pos = 0
        self._direction = direction
        self._start = start

    def _fail(self, reason: str) -> ProtocolViolation:
        return ProtocolViolation(self._direction, self._start, reason)

    def remaining(self) -> int:
        return len(self._buf) - self._pos

    def take(self, n: int) -> bytes:
        if n < 0 or self._pos + n > len(self._buf):
            raise self._fail("payload shorter than declared fields")
        chunk = self._buf[self._pos : self._pos + n]
        self._pos += n
        return chunk

    def int16(self) -> int:
        return int.from_bytes(self.take(2), "big", signed=True)

    def uint16(self) -> int:
        return int.from_bytes(self.take(2), "big", signed=False)

    def int32(self) -> int:
        return int.from_bytes(self.take(4), "big", signed=True)

    def byte(self) -> int:
        return self.take(1)[0]

    def cstring(self) -> str:
        """Read a NUL-terminated UTF-8 string (the NUL is consumed)."""
        end = self._buf.find(b"\x00", self._pos)
        if end < 0:
            raise self._fail("unterminated NUL string")
        raw = self._buf[self._pos : end]
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise self._fail(f"protocol string is not valid UTF-8: {exc}")
        self._pos = end + 1
        return text

    def expect_end(self) -> None:
        if self._pos != len(self._buf):
            raise self._fail(
                f"{len(self._buf) - self._pos} trailing byte(s) in payload"
            )

    def expect_empty(self) -> None:
        if self._buf:
            raise self._fail("payload must be empty")
