"""Raw PostgreSQL 17 message builders for byte-level acceptance tests.

Everything here is hand-rolled framing: each message is the type byte,
a 4-byte big-endian length (length bytes including itself) and payload.
"""

from __future__ import annotations


def frame(mtype: str, payload: bytes) -> bytes:
    return (
        mtype.encode("ascii")
        + (len(payload) + 4).to_bytes(4, "big")
        + payload
    )


def cstr(text: str) -> bytes:
    return text.encode("utf-8") + b"\x00"


# -- client messages -------------------------------------------------------


def parse(statement: str, query: str, param_oids: list[int] | None = None
          ) -> bytes:
    p = cstr(statement) + cstr(query)
    param_oids = param_oids or []
    p += len(param_oids).to_bytes(2, "big")
    for oid in param_oids:
        p += oid.to_bytes(4, "big", signed=True)
    return frame("P", p)


def bind(portal: str, statement: str,
         params: list[bytes | None] | None = None,
         param_formats: list[int] | None = None,
         result_formats: list[int] | None = None) -> bytes:
    params = [] if params is None else params
    if param_formats is None:
        param_formats = [0] * len(params)
    if result_formats is None:
        result_formats = [0]
    p = cstr(portal) + cstr(statement)
    p += len(param_formats).to_bytes(2, "big")
    for fc in param_formats:
        p += fc.to_bytes(2, "big", signed=True)
    p += len(params).to_bytes(2, "big")
    for value in params:
        if value is None:
            p += (-1).to_bytes(4, "big", signed=True)
        else:
            p += len(value).to_bytes(4, "big") + value
    p += len(result_formats).to_bytes(2, "big")
    for fc in result_formats:
        p += fc.to_bytes(2, "big", signed=True)
    return frame("B", p)


def describe_portal(name: str) -> bytes:
    return frame("D", b"P" + cstr(name))


def describe_statement(name: str) -> bytes:
    return frame("D", b"S" + cstr(name))


def execute(portal: str, max_rows: int = 0) -> bytes:
    return frame("E", cstr(portal) + max_rows.to_bytes(4, "big", signed=True))


def close(kind: str, name: str) -> bytes:
    return frame("C", kind.encode("ascii") + cstr(name))


def flush() -> bytes:
    return frame("H", b"")


def sync() -> bytes:
    return frame("S", b"")


# -- server messages -------------------------------------------------------


def parse_complete() -> bytes:
    return frame("1", b"")


def bind_complete() -> bytes:
    return frame("2", b"")


def close_complete() -> bytes:
    return frame("3", b"")


def row_description(columns: list[tuple[str, int, int]]) -> bytes:
    p = len(columns).to_bytes(2, "big")
    for name, oid, fmt in columns:
        p += cstr(name)
        p += (0).to_bytes(4, "big")          # table OID
        p += (0).to_bytes(2, "big")          # column attribute number
        p += oid.to_bytes(4, "big", signed=True)
        p += (-1).to_bytes(2, "big", signed=True)  # type size
        p += (-1).to_bytes(4, "big", signed=True)  # type modifier
        p += fmt.to_bytes(2, "big", signed=True)   # format code
    return frame("T", p)


def data_row(values: list[bytes | None]) -> bytes:
    p = len(values).to_bytes(2, "big")
    for value in values:
        if value is None:
            p += (-1).to_bytes(4, "big", signed=True)
        else:
            p += len(value).to_bytes(4, "big") + value
    return frame("D", p)


def command_complete(tag: str = "SELECT 1") -> bytes:
    return frame("C", cstr(tag))


def portal_suspended() -> bytes:
    return frame("s", b"")


def ready(status: str = "I") -> bytes:
    return frame("Z", status.encode("ascii"))


def error_response(fields: list[tuple[str, str]] | None = None) -> bytes:
    fields = fields or [("S", "ERROR"), ("C", "42P01"),
                        ("M", "relation does not exist")]
    p = b""
    for code, text in fields:
        p += code.encode("ascii") + cstr(text)
    p += b"\x00"
    return frame("E", p)


def no_data() -> bytes:
    return frame("n", b"")


def empty_query() -> bytes:
    return frame("I", b"")
