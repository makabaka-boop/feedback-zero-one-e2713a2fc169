"""Extended-query correlation state machine (PG17 §53.2.3, §53.2.4).

The module consumes already-framed client and server byte streams and
correlates requests with their replies, emulating the server-side object
lifecycle of prepared statements and portals (unnamed objects replaced
on reuse, portals closed at transaction/Sync boundaries, ...).

Only Parse, Bind, portal Describe, Execute, Close, Flush and Sync on the
client side, and their direct replies on the server side, are accepted.
A violation anywhere rejects the entire run.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from .framing import PayloadReader, ProtocolViolation, RawMessage


# ---------------------------------------------------------------------------
# Parsed client messages
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Parse:
    statement: str
    query: str
    param_type_oids: tuple[int, ...]


@dataclass(frozen=True)
class Bind:
    portal: str
    statement: str
    param_formats: tuple[int, ...]
    params: tuple[bytes | None, ...]
    result_formats: tuple[int, ...]


@dataclass(frozen=True)
class Describe:
    kind: str          # always "P": statement ('S') describes are rejected
    name: str


@dataclass(frozen=True)
class Execute:
    portal: str
    max_rows: int


@dataclass(frozen=True)
class Close:
    kind: str          # "S" statement or "P" portal
    name: str


def parse_client(msg: RawMessage):
    r = PayloadReader(msg.payload, "client", msg.start)
    t = msg.type
    if t == "P":
        statement = r.cstring()
        query = r.cstring()
        if not query:
            raise ProtocolViolation(
                "client", msg.start, "Parse query must be a non-empty SQL"
            )
        count = r.uint16()
        oids = tuple(r.int32() for _ in range(count))
        r.expect_end()
        return Parse(statement, query, oids)
    if t == "B":
        portal = r.cstring()
        statement = r.cstring()
        nfmt = r.uint16()
        param_formats = tuple(r.int16() for _ in range(nfmt))
        for fc in param_formats:
            if fc not in (0, 1):
                raise ProtocolViolation(
                    "client", msg.start,
                    f"invalid parameter format code {fc}",
                )
        nparam = r.uint16()
        params: list[bytes | None] = []
        for _ in range(nparam):
            size = r.int32()
            if size < 0:
                params.append(None)          # SQL NULL
            else:
                params.append(r.take(size))  # raw bytes, never decoded
        nrfmt = r.uint16()
        result_formats = tuple(r.int16() for _ in range(nrfmt))
        for fc in result_formats:
            if fc not in (0, 1):
                raise ProtocolViolation(
                    "client", msg.start,
                    f"invalid result format code {fc}",
                )
        r.expect_end()
        return Bind(portal, statement, param_formats, tuple(params),
                    result_formats)
    if t == "D":
        kind = chr(r.byte())
        if kind not in ("S", "P"):
            raise ProtocolViolation(
                "client", msg.start, f"unknown Describe target {kind!r}"
            )
        if kind == "S":
            raise ProtocolViolation(
                "client",
                msg.start,
                "statement Describe ('S') is not accepted, only portals",
            )
        name = r.cstring()
        r.expect_end()
        return Describe(kind, name)
    if t == "E":
        portal = r.cstring()
        max_rows = r.int32()
        if max_rows < 0:
            raise ProtocolViolation(
                "client", msg.start, "Execute max-rows must be non-negative"
            )
        r.expect_end()
        return Execute(portal, max_rows)
    if t == "C":
        kind = chr(r.byte())
        if kind not in ("S", "P"):
            raise ProtocolViolation(
                "client", msg.start, f"unknown Close target {kind!r}"
            )
        name = r.cstring()
        r.expect_end()
        return Close(kind, name)
    if t in ("H", "S"):
        r.expect_empty()
        return None
    raise ProtocolViolation(
        "client", msg.start, f"unsupported client message {t!r}"
    )


# ---------------------------------------------------------------------------
# Parsed server messages
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RowDescription:
    # each column: (name, type OID, format code)
    columns: tuple[tuple[str, int, int], ...]


@dataclass(frozen=True)
class DataRow:
    values: tuple[bytes | None, ...]


def parse_row_description(msg: RawMessage) -> RowDescription:
    r = PayloadReader(msg.payload, "server", msg.start)
    count = r.uint16()
    columns: list[tuple[str, int, int]] = []
    for _ in range(count):
        name = r.cstring()
        r.take(6)  # table OID (4) + column attribute number (2), ignored
        type_oid = r.int32()
        r.take(6)  # type size (2) + type modifier (4), ignored
        format_code = r.int16()
        if format_code not in (0, 1):
            raise ProtocolViolation(
                "server",
                msg.start,
                f"invalid column format code {format_code}",
            )
        columns.append((name, type_oid, format_code))
    r.expect_end()
    return RowDescription(tuple(columns))


def parse_data_row(msg: RawMessage) -> DataRow:
    r = PayloadReader(msg.payload, "server", msg.start)
    count = r.uint16()
    values: list[bytes | None] = []
    for _ in range(count):
        size = r.int32()
        if size < 0:
            values.append(None)
        else:
            values.append(r.take(size))
    r.expect_end()
    return DataRow(tuple(values))


def parse_ready(msg: RawMessage) -> str:
    r = PayloadReader(msg.payload, "server", msg.start)
    status = chr(r.byte())
    r.expect_end()
    if status not in ("I", "T", "E"):
        raise ProtocolViolation(
            "server", msg.start, f"unknown ReadyForQuery status {status!r}"
        )
    return status


def parse_error(msg: RawMessage) -> None:
    """Validate an ErrorResponse structure; field text is not needed."""
    r = PayloadReader(msg.payload, "server", msg.start)
    saw_terminator = False
    while r.remaining():
        field = chr(r.byte())
        if field == "\x00":
            saw_terminator = True
            break
        r.cstring()
    if not saw_terminator:
        raise ProtocolViolation(
            "server", msg.start, "ErrorResponse missing terminating NUL"
        )
    r.expect_end()


# ---------------------------------------------------------------------------
# Server-side object model and output records
# ---------------------------------------------------------------------------


@dataclass
class Statement:
    sql: str
    param_oids: tuple[int, ...]


@dataclass
class Portal:
    sql: str                       # snapshot fixed at Bind time
    params: tuple[bytes | None, ...]
    columns: tuple[tuple[str, int, int], ...] | None = None
    described: bool = False


@dataclass
class OutputItem:
    id: int
    sql: str | None
    params: list[str | None] | None
    columns: list[list] | None
    rows: list[list]
    status: str


class _ServerCursor:
    """Ordered view over the framed server messages."""

    def __init__(self, messages: list[RawMessage], client: list[RawMessage]):
        self._messages = messages
        self._client = client
        self.index = 0

    def peek(self) -> RawMessage:
        if self.index >= len(self._messages):
            last = self._client[-1] if self._client else None
            offset = last.start if last is not None else 0
            raise ProtocolViolation(
                "server", offset, "missing server reply before end of stream"
            )
        return self._messages[self.index]

    def pop(self, allowed: str) -> RawMessage:
        msg = self.peek()
        if msg.type not in allowed:
            raise ProtocolViolation(
                "server",
                msg.start,
                f"unexpected reply {msg.type!r}, wanted one of {allowed!r}",
            )
        self.index += 1
        return msg

    def exhausted(self) -> bool:
        return self.index >= len(self._messages)

    def require_exhausted(self) -> None:
        if not self.exhausted():
            extra = self._messages[self.index]
            raise ProtocolViolation(
                "server",
                extra.start,
                "unsolicited server message with no matching request",
            )


def _b64(value: bytes) -> str:
    # Empty bytes become an empty string, never an encoded value.
    if value == b"":
        return ""
    return base64.b64encode(value).decode("ascii")


def _encode_params(params: tuple[bytes | None, ...]) -> list[str | None]:
    return [None if p is None else _b64(p) for p in params]


def _encode_row(values: tuple[bytes | None, ...]) -> list[str | None]:
    return [None if v is None else _b64(v) for v in values]


# ---------------------------------------------------------------------------
# Main correlation entry point
# ---------------------------------------------------------------------------


def correlate(client_msgs: list[RawMessage],
              server_msgs: list[RawMessage]) -> list[dict]:
    # The only legal empty capture: both directions empty -> empty result.
    if not client_msgs and not server_msgs:
        return []
    if not client_msgs:
        raise ProtocolViolation(
            "client",
            0,
            "empty client stream while server stream is non-empty",
        )

    statements: dict[str, Statement] = {}
    portals: dict[str, Portal] = {}
    items: list[OutputItem] = []
    # Request queue: ("other", kind), ("describe", portal), ("sync",),
    # ("execute", Execute, OutputItem, Portal).
    pending: list[tuple] = []
    skip_until_sync = False
    server = _ServerCursor(server_msgs, client_msgs)

    for cmsg in client_msgs:
        parsed = parse_client(cmsg)
        mtype = cmsg.type

        # -- Error recovery: everything up to Sync is skipped -------------
        if skip_until_sync:
            if mtype == "S":
                skip_until_sync = False
                pending.append(("sync",))
                _drain(pending, statements, portals, items, server)
            elif mtype == "E":
                # Skipped Execute still occupies a contiguous output slot.
                items.append(OutputItem(len(items), None, None, None,
                                        [], "skipped"))
            continue

        if mtype == "P":
            assert isinstance(parsed, Parse)
            # Re-parsing a name replaces the statement.
            statements[parsed.statement] = Statement(
                parsed.query, parsed.param_type_oids
            )
            pending.append(("other", "parse"))

        elif mtype == "B":
            assert isinstance(parsed, Bind)
            stmt = statements.get(parsed.statement)
            if stmt is None:
                raise ProtocolViolation(
                    "client",
                    cmsg.start,
                    f"Bind references non-existent statement "
                    f"{parsed.statement!r}",
                )
            # Binding an existing portal name replaces the portal; its SQL
            # and parameter snapshot is fixed at this moment.
            portals[parsed.portal] = Portal(sql=stmt.sql,
                                            params=parsed.params)
            pending.append(("other", "bind"))

        elif mtype == "D":
            assert isinstance(parsed, Describe)
            portal = portals.get(parsed.name)
            if portal is None:
                raise ProtocolViolation(
                    "client",
                    cmsg.start,
                    f"Describe references non-existent portal {parsed.name!r}",
                )
            pending.append(("describe", portal))

        elif mtype == "E":
            assert isinstance(parsed, Execute)
            portal = portals.get(parsed.portal)
            if portal is None:
                raise ProtocolViolation(
                    "client",
                    cmsg.start,
                    f"Execute references non-existent portal {parsed.portal!r}",
                )
            if not portal.described:
                raise ProtocolViolation(
                    "client",
                    cmsg.start,
                    "Execute references a portal that was not successfully "
                    "described",
                )
            assert portal.columns is not None
            item = OutputItem(
                id=len(items),
                sql=portal.sql,
                params=_encode_params(portal.params),
                columns=[list(c) for c in portal.columns],
                rows=[],
                status="",
            )
            items.append(item)
            pending.append(("execute", parsed, item, portal))

        elif mtype == "C":
            assert isinstance(parsed, Close)
            if parsed.kind == "S":
                if parsed.name not in statements:
                    raise ProtocolViolation(
                        "client",
                        cmsg.start,
                        f"Close references non-existent statement "
                        f"{parsed.name!r}",
                    )
                del statements[parsed.name]
            else:
                if parsed.name not in portals:
                    raise ProtocolViolation(
                        "client",
                        cmsg.start,
                        f"Close references non-existent portal {parsed.name!r}",
                    )
                del portals[parsed.name]
            pending.append(("other", "close"))

        elif mtype == "H":
            if _drain(pending, statements, portals, items, server):
                skip_until_sync = True
            continue

        elif mtype == "S":
            pending.append(("sync",))

        if _drain(pending, statements, portals, items, server):
            skip_until_sync = True

    if client_msgs[-1].type != "S":
        raise ProtocolViolation(
            "client",
            client_msgs[-1].start,
            "stream does not end with Sync",
        )

    server.require_exhausted()

    return [
        {
            "id": it.id,
            "sql": it.sql,
            "params": it.params,
            "columns": it.columns,
            "rows": it.rows,
            "status": it.status,
        }
        for it in items
    ]


def _drain(pending: list[tuple], statements: dict[str, Statement],
           portals: dict[str, Portal], items: list[OutputItem],
           server: _ServerCursor) -> bool:
    """Correlate queued requests with the ordered server replies.

    Returns True when an Execute failed before its Sync was reached, so
    the caller must keep skipping client messages until the next Sync.
    """
    while pending:
        entry = pending.pop(0)
        kind = entry[0]

        if kind == "other":
            # Parse -> ParseComplete(1), Bind -> BindComplete(2),
            # Close -> CloseComplete(3); the replies are not interchangeable.
            wanted = {"parse": "1", "bind": "2", "close": "3"}[entry[1]]
            server.pop(wanted)
            continue

        if kind == "describe":
            portal: Portal = entry[1]
            msg = server.pop("Tn")
            if msg.type == "n":
                # NoData cannot answer a non-empty SELECT portal describe.
                raise ProtocolViolation(
                    "server",
                    msg.start,
                    "NoData reply to portal Describe is not accepted",
                )
            desc = parse_row_description(msg)
            portal.columns = desc.columns
            portal.described = True
            continue

        if kind == "sync":
            _consume_sync(server, statements, portals)
            continue

        # kind == "execute"
        _, execute, item, portal = entry
        _run_execute(execute, item, portal, server)
        if item.status == "error":
            # Remaining queued requests (all before this point in the
            # pipeline) produce no ordinary replies. If a Sync is already
            # queued it still consumes ReadyForQuery and recovery ends;
            # otherwise the outer loop keeps skipping until Sync arrives.
            sync_seen = _skip_pending_to_sync(pending, statements,
                                              portals, server)
            return not sync_seen
    return False


def _consume_sync(server: _ServerCursor,
                  statements: dict[str, Statement],
                  portals: dict[str, Portal]) -> None:
    msg = server.pop("Z")
    status = parse_ready(msg)
    if status != "I":
        raise ProtocolViolation(
            "server",
            msg.start,
            f"ReadyForQuery status {status!r}, required idle 'I'",
        )
    # End of the implicit transaction: every portal is released and the
    # unnamed prepared statement is released; named statements persist,
    # matching PG17 lifecycle rules.
    portals.clear()
    statements.pop("", None)


def _run_execute(execute: Execute, item: OutputItem, portal: Portal,
                 server: _ServerCursor) -> None:
    assert portal.columns is not None
    ncols = len(portal.columns)
    while True:
        msg = server.peek()
        if msg.type == "D":
            server.pop("D")
            row = parse_data_row(msg)
            if len(row.values) != ncols:
                raise ProtocolViolation(
                    "server",
                    msg.start,
                    f"DataRow has {len(row.values)} columns, portal "
                    f"described {ncols}",
                )
            # Rows already received are retained even if an error follows.
            item.rows.append(_encode_row(row.values))
            continue
        if msg.type == "s":
            server.pop("s")
            if execute.max_rows == 0:
                raise ProtocolViolation(
                    "server",
                    msg.start,
                    "PortalSuspended with unlimited row count (max_rows=0)",
                )
            item.status = "paused"
            return
        if msg.type == "C":
            server.pop("C")
            r = PayloadReader(msg.payload, "server", msg.start)
            r.cstring()  # command tag
            r.expect_end()
            item.status = "completed"
            return
        if msg.type == "E":
            server.pop("E")
            parse_error(msg)
            item.status = "error"
            return
        raise ProtocolViolation(
            "server",
            msg.start,
            f"unexpected reply {msg.type!r} during Execute",
        )


def _skip_pending_to_sync(pending: list[tuple],
                          statements: dict[str, Statement],
                          portals: dict[str, Portal],
                          server: _ServerCursor) -> bool:
    """Drop queued post-error requests; only a Sync keeps its reply.

    Returns True if the recovering Sync was found and consumed.
    """
    while pending:
        entry = pending.pop(0)
        if entry[0] == "sync":
            _consume_sync(server, statements, portals)
            return True
        # Everything else created no object and gets no ordinary reply.
    return False
