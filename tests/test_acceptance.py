"""Byte-level acceptance tests for the pgcap capture parser.

Run with:
    python -I -m unittest -v tests.test_acceptance
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pgcap import ProtocolViolation, correlate, frame_stream  # noqa: E402
import pgmsg as m  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "pgcap_cli.py"


def parse_both(client: bytes, server: bytes):
    return correlate(frame_stream(client, "client"),
                     frame_stream(server, "server"))


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def simple_flow(sql="SELECT 1", params=None, rows=None,
                columns=None, portal="", statement=""):
    """One unnamed/named portal executed to completion in one Sync."""
    columns = columns or [("a", 23, 0)]
    rows = rows or []
    client = (m.parse(statement, sql) + m.bind(portal, statement, params)
              + m.describe_portal(portal) + m.execute(portal) + m.sync())
    server = (m.parse_complete() + m.bind_complete()
              + m.row_description(columns)
              + b"".join(m.data_row(r) for r in rows)
              + m.command_complete() + m.ready())
    return client, server


class HappyPathTests(unittest.TestCase):

    def test_double_empty_stream_is_empty_array(self):
        self.assertEqual(parse_both(b"", b""), [])

    def test_basic_unnamed_completed(self):
        client, server = simple_flow(rows=[[b"1"]])
        out = parse_both(client, server)
        self.assertEqual(len(out), 1)
        item = out[0]
        self.assertEqual(item["id"], 0)
        self.assertEqual(item["sql"], "SELECT 1")
        self.assertEqual(item["params"], [])
        self.assertEqual(item["columns"], [["a", 23, 0]])
        self.assertEqual(item["rows"], [[b64(b"1")]])
        self.assertEqual(item["status"], "completed")

    def test_named_objects_pipeline_two_executes(self):
        client = (
            m.parse("s1", "SELECT $1::int AS x", [23])
            + m.bind("p1", "s1", [b"7"])
            + m.describe_portal("p1")
            + m.execute("p1")
            + m.bind("p2", "s1", [b"9"])
            + m.describe_portal("p2")
            + m.execute("p2")
            + m.sync()
        )
        server = (
            m.parse_complete() + m.bind_complete()
            + m.row_description([("x", 23, 0)])
            + m.data_row([b"7"]) + m.command_complete()
            + m.bind_complete()
            + m.row_description([("x", 23, 0)])
            + m.data_row([b"9"]) + m.command_complete()
            + m.ready()
        )
        out = parse_both(client, server)
        self.assertEqual([i["id"] for i in out], [0, 1])
        self.assertEqual(out[0]["params"], [b64(b"7")])
        self.assertEqual(out[1]["params"], [b64(b"9")])
        self.assertTrue(all(i["status"] == "completed" for i in out))

    def test_suspend_resume_records_only_each_fetch_rows(self):
        # Portal p: first Execute max_rows=1 -> A then suspended;
        # resume -> B then completion.
        client = (
            m.parse("", "SELECT v")
            + m.bind("p", "")
            + m.describe_portal("p")
            + m.execute("p", max_rows=1)
            + m.flush()
            + m.execute("p", max_rows=1)
            + m.sync()
        )
        server = (
            m.parse_complete() + m.bind_complete()
            + m.row_description([("v", 25, 0)])
            + m.data_row([b"A"]) + m.portal_suspended()
            + m.data_row([b"B"]) + m.command_complete() + m.ready()
        )
        out = parse_both(client, server)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["status"], "paused")
        self.assertEqual(out[0]["rows"], [[b64(b"A")]])
        self.assertEqual(out[1]["status"], "completed")
        self.assertEqual(out[1]["rows"], [[b64(b"B")]])

    def test_spec_example_qq_qg(self):
        # The task's example: A then pause, B then complete.
        client = (
            m.parse("", "SELECT x") + m.bind("p", "")
            + m.describe_portal("p")
            + m.execute("p", 1) + m.flush()
            + m.execute("p", 1) + m.sync()
        )
        server = (
            m.parse_complete() + m.bind_complete()
            + m.row_description([("x", 17, 1)])
            + m.data_row([b"A"]) + m.portal_suspended()
            + m.data_row([b"B"]) + m.command_complete() + m.ready()
        )
        out = parse_both(client, server)
        self.assertEqual(out[0]["rows"], [["QQ=="]])
        self.assertEqual(out[1]["rows"], [["Qg=="]])
        self.assertEqual(out[0]["columns"], [["x", 17, 1]])

    def test_null_and_empty_byte_values(self):
        client, server = simple_flow(
            params=[None, b"", b"\x00\x01"],
            rows=[[None], [b""], [b"\x00\x01"]],
            columns=[("c", 25, 1)],
        )
        out = parse_both(client, server)
        self.assertEqual(out[0]["params"],
                         [None, "", b64(b"\x00\x01")])
        self.assertEqual(out[0]["rows"],
                         [[None], [""], [b64(b"\x00\x01")]])

    def test_multiple_syncs_named_statement_survives(self):
        c1, s1 = simple_flow(sql="SELECT 1", statement="st", portal="po")
        # Second cycle reuses the named statement (no re-Parse) but portals
        # were destroyed at Sync, so rebind + redescribe.
        c2 = (m.bind("po2", "st") + m.describe_portal("po2")
              + m.execute("po2") + m.sync())
        s2 = (m.bind_complete() + m.row_description([("a", 23, 0)])
              + m.command_complete() + m.ready())
        out = parse_both(c1 + c2, s1 + s2)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[1]["sql"], "SELECT 1")

    def test_close_statement_and_portal(self):
        client = (
            m.parse("s", "SELECT 1") + m.bind("p", "s")
            + m.describe_portal("p") + m.execute("p")
            + m.close("P", "p") + m.close("S", "s") + m.sync()
        )
        server = (
            m.parse_complete() + m.bind_complete()
            + m.row_description([("a", 23, 0)])
            + m.command_complete()
            + m.close_complete() + m.close_complete() + m.ready()
        )
        out = parse_both(client, server)
        self.assertEqual(out[0]["status"], "completed")

    def test_rebind_same_portal_name_replaces_snapshot(self):
        client = (
            m.parse("s", "SELECT $1")
            + m.bind("p", "s", [b"1"]) + m.describe_portal("p")
            + m.execute("p")
            + m.bind("p", "s", [b"2"]) + m.describe_portal("p")
            + m.execute("p") + m.sync()
        )
        server = (
            m.parse_complete()
            + m.bind_complete() + m.row_description([("a", 23, 0)])
            + m.command_complete()
            + m.bind_complete() + m.row_description([("a", 23, 0)])
            + m.command_complete() + m.ready()
        )
        out = parse_both(client, server)
        self.assertEqual(out[0]["params"], [b64(b"1")])
        self.assertEqual(out[1]["params"], [b64(b"2")])


class ErrorRecoveryTests(unittest.TestCase):

    def _pipeline_with_error(self):
        client = (
            m.parse("", "SELECT 1") + m.bind("p", "")
            + m.describe_portal("p")
            + m.execute("p")          # fails at runtime
            + m.bind("q", "")         # skipped
            + m.execute("q")          # skipped slot
            + m.sync()
        )
        server = (
            m.parse_complete() + m.bind_complete()
            + m.row_description([("a", 23, 0)])
            + m.data_row([b"kept"])
            + m.error_response()
            + m.ready()
        )
        return client, server

    def test_execute_error_keeps_rows_and_skips_rest(self):
        client, server = self._pipeline_with_error()
        out = parse_both(client, server)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["status"], "error")
        self.assertEqual(out[0]["rows"], [[b64(b"kept")]])
        self.assertEqual(out[1]["status"], "skipped")
        self.assertIsNone(out[1]["sql"])
        self.assertIsNone(out[1]["params"])
        self.assertIsNone(out[1]["columns"])
        self.assertEqual(out[1]["rows"], [])

    def test_error_with_sync_already_pipelined(self):
        # Error happens, then more requests, then Sync was already queued.
        client = (
            m.parse("", "SELECT 1") + m.bind("p", "")
            + m.describe_portal("p") + m.execute("p")
            + m.execute("p") + m.sync()
        )
        server = (
            m.parse_complete() + m.bind_complete()
            + m.row_description([("a", 23, 0)])
            + m.error_response() + m.ready()
        )
        out = parse_both(client, server)
        self.assertEqual([i["status"] for i in out], ["error", "skipped"])

    def test_error_then_new_transaction_after_sync(self):
        # After recovery, a fresh portal created post-Sync works again.
        c1 = (
            m.parse("", "SELECT 1") + m.bind("p", "")
            + m.describe_portal("p") + m.execute("p") + m.sync()
        )
        s1 = (
            m.parse_complete() + m.bind_complete()
            + m.row_description([("a", 23, 0)])
            + m.error_response() + m.ready()
        )
        c2, s2 = simple_flow(sql="SELECT 2")
        out = parse_both(c1 + c2, s1 + s2)
        self.assertEqual(out[0]["status"], "error")
        self.assertEqual(out[1]["status"], "completed")
        self.assertEqual(out[1]["sql"], "SELECT 2")

    def test_skipped_execute_ids_remain_contiguous(self):
        client = (
            m.parse("", "SELECT 1") + m.bind("p", "")
            + m.describe_portal("p") + m.execute("p")
            + m.execute("p") + m.execute("p") + m.sync()
        )
        server = (
            m.parse_complete() + m.bind_complete()
            + m.row_description([("a", 23, 0)])
            + m.error_response() + m.ready()
        )
        out = parse_both(client, server)
        self.assertEqual([i["id"] for i in out], [0, 1, 2])
        self.assertEqual([i["status"] for i in out],
                         ["error", "skipped", "skipped"])


class FramingRejectionTests(unittest.TestCase):

    def _assert_violation(self, client, server, direction):
        with self.assertRaises(ProtocolViolation) as ctx:
            parse_both(client, server)
        self.assertEqual(ctx.exception.direction, direction)

    def test_truncated_header_client(self):
        self._assert_violation(b"P\x00\x00", b"", "client")

    def test_truncated_payload_server(self):
        client, _ = simple_flow()
        # RowDescription header promising many bytes, truncated.
        bad = (m.parse_complete() + m.bind_complete()
               + b"T\x00\x01\x00\x00")
        self._assert_violation(client, bad, "server")

    def test_length_below_four(self):
        self._assert_violation(b"P\x00\x00\x00\x03", b"", "client")

    def test_trailing_bytes(self):
        client, server = simple_flow()
        self._assert_violation(client + b"X", server, "client")

    def test_unknown_client_message_type(self):
        # 'Q' simple query is outside the accepted extended-query set.
        self._assert_violation(
            b"Q\x00\x00\x00\x0dselect 1\x00", b"", "client")

    def test_unknown_server_message_type(self):
        client = m.sync()
        self._assert_violation(client, b"Z\x00\x00\x00\x05I" + b"X\x00\x00\x00\x04",
                               "server")

    def test_empty_client_nonempty_server(self):
        self._assert_violation(b"", m.ready(), "client")

    def test_server_stream_truncated_missing_reply(self):
        client, server = simple_flow()
        self._assert_violation(client, server[:-5], "server")


class OrderAndRuleRejectionTests(unittest.TestCase):

    def _assert_violation(self, client, server, direction):
        with self.assertRaises(ProtocolViolation) as ctx:
            parse_both(client, server)
        self.assertEqual(ctx.exception.direction, direction)

    def test_client_not_ending_with_sync(self):
        client = (m.parse("", "SELECT 1") + m.bind("p", ""))
        server = m.parse_complete() + m.bind_complete()
        self._assert_violation(client, server, "client")

    def test_unsolicited_server_message(self):
        client = m.sync()
        server = m.ready() + m.command_complete()
        self._assert_violation(client, server, "server")

    def test_missing_server_reply(self):
        client, server = simple_flow()
        self._assert_violation(client, server[:-len(m.ready())], "server")

    def test_wrong_reply_order(self):
        # BindComplete ('2') where ParseComplete ('1') is expected.
        client = (m.parse("", "SELECT 1") + m.sync())
        server = m.bind_complete() + m.ready()
        self._assert_violation(client, server, "server")
    def test_bind_unknown_statement(self):
        client = m.bind("p", "ghost") + m.sync()
        self._assert_violation(client, m.ready(), "client")

    def test_describe_unknown_portal(self):
        client = m.describe_portal("ghost") + m.sync()
        self._assert_violation(client, m.ready(), "client")

    def test_execute_undescribed_portal(self):
        client = (m.parse("", "SELECT 1") + m.bind("p", "")
                  + m.execute("p") + m.sync())
        server = (m.parse_complete() + m.bind_complete() + m.ready())
        self._assert_violation(client, server, "client")

    def test_execute_unknown_portal(self):
        client = m.execute("ghost") + m.sync()
        self._assert_violation(client, m.ready(), "client")

    def test_statement_describe_rejected(self):
        client = m.describe_statement("") + m.sync()
        self._assert_violation(client, m.ready(), "client")

    def test_nodata_rejected_for_portal_describe(self):
        client = (m.parse("", "SELECT 1") + m.bind("p", "")
                  + m.describe_portal("p") + m.sync())
        server = (m.parse_complete() + m.bind_complete()
                  + m.no_data() + m.ready())
        self._assert_violation(client, server, "server")

    def test_empty_query_response_rejected(self):
        # 'I' is not an allowed server type at all.
        client = m.sync()
        self._assert_violation(client, m.empty_query(), "server")

    def test_ready_status_must_be_idle(self):
        client = m.sync()
        self._assert_violation(client, m.ready("T"), "server")
        self._assert_violation(client, m.ready("E"), "server")

    def test_portal_suspended_with_max_rows_zero(self):
        client, _ = simple_flow()
        server = (
            m.parse_complete() + m.bind_complete()
            + m.row_description([("a", 23, 0)])
            + m.portal_suspended() + m.ready()
        )
        self._assert_violation(client, server, "server")

    def test_error_outside_execute_rejects_run(self):
        # Error answering a Bind is not permitted (only Execute may error).
        client = (m.parse("", "SELECT 1") + m.bind("p", "") + m.sync())
        server = m.parse_complete() + m.error_response() + m.ready()
        self._assert_violation(client, server, "server")

    def test_extra_reply_during_skip_rejected(self):
        # After Execute error, an ordinary reply before ReadyForQuery is
        # illegal.
        client = (
            m.parse("", "SELECT 1") + m.bind("p", "")
            + m.describe_portal("p") + m.execute("p")
            + m.execute("p") + m.sync()
        )
        server = (
            m.parse_complete() + m.bind_complete()
            + m.row_description([("a", 23, 0)])
            + m.error_response()
            + m.bind_complete()       # illegal: skipped bind gets no reply
            + m.ready()
        )
        self._assert_violation(client, server, "server")

    def test_data_row_column_count_mismatch(self):
        client, _ = simple_flow(columns=[("a", 23, 0), ("b", 23, 0)])
        server = (
            m.parse_complete() + m.bind_complete()
            + m.row_description([("a", 23, 0), ("b", 23, 0)])
            + m.data_row([b"only-one"])
            + m.command_complete() + m.ready()
        )
        self._assert_violation(client, server, "server")

    def test_invalid_utf8_protocol_string(self):
        bad = b"P" + (12).to_bytes(4, "big") + b"\x00\xff\xfe\x00\x00\x00"
        self._assert_violation(bad, b"", "client")

    def test_close_unknown_object(self):
        self._assert_violation(m.close("P", "x") + m.sync(),
                               m.ready(), "client")

    def test_unnamed_portal_released_at_sync(self):
        c1, s1 = simple_flow()  # uses unnamed portal/statement
        # Reuse without rebind: portal no longer exists after Sync.
        c2 = m.execute("") + m.sync()
        self._assert_violation(c1 + c2, s1 + m.ready(), "client")

    def test_unnamed_statement_replaced_on_reparse(self):
        client = (
            m.parse("", "SELECT 1")
            + m.parse("", "SELECT 2")
            + m.bind("p", "") + m.describe_portal("p")
            + m.execute("p") + m.sync()
        )
        server = (
            m.parse_complete() + m.parse_complete()
            + m.bind_complete() + m.row_description([("a", 23, 0)])
            + m.command_complete() + m.ready()
        )
        out = parse_both(client, server)
        self.assertEqual(out[0]["sql"], "SELECT 2")

    def test_multiple_rows_accumulate_in_one_item(self):
        client, _ = simple_flow()
        server = (
            m.parse_complete() + m.bind_complete()
            + m.row_description([("a", 23, 0)])
            + m.data_row([b"1"]) + m.data_row([b"2"]) + m.data_row([b"3"])
            + m.command_complete("SELECT 3") + m.ready()
        )
        out = parse_both(client, server)
        self.assertEqual(out[0]["rows"],
                         [[b64(b"1")], [b64(b"2")], [b64(b"3")]])

    def test_flush_delivers_early_replies_within_one_sync(self):
        client = (
            m.parse("", "SELECT 1") + m.bind("p", "") + m.flush()
            + m.describe_portal("p") + m.execute("p") + m.sync()
        )
        server = (
            m.parse_complete() + m.bind_complete()
            + m.row_description([("a", 23, 0)])
            + m.command_complete() + m.ready()
        )
        out = parse_both(client, server)
        self.assertEqual(out[0]["status"], "completed")

    def test_invalid_bind_format_code_rejected(self):
        bad_bind = m.bind("p", "", param_formats=[9])
        client = m.parse("", "SELECT 1") + bad_bind + m.sync()
        self._assert_violation(client,
                               m.parse_complete() + m.ready(), "client")

    def test_skipped_requests_create_no_objects_for_later_cycle(self):
        # A Bind+Describe+Execute after the error are skipped, so the portal
        # must not exist after the recovering Sync; referencing it later is a
        # client-side violation.
        client = (
            m.parse("", "SELECT 1") + m.bind("p", "")
            + m.describe_portal("p") + m.execute("p")
            + m.bind("p2", "") + m.describe_portal("p2")
            + m.execute("p2") + m.sync()
            + m.execute("p2") + m.sync()
        )
        server = (
            m.parse_complete() + m.bind_complete()
            + m.row_description([("a", 23, 0)])
            + m.error_response() + m.ready()
            + m.ready()  # reply to the second Sync, if it were reached
        )
        self._assert_violation(client, server, "client")


class CliTests(unittest.TestCase):

    def _run_cli(self, client: bytes, server: bytes, out: Path):
        d = Path(tempfile.mkdtemp())
        cp = d / "client.bin"
        sp = d / "server.bin"
        cp.write_bytes(client)
        sp.write_bytes(server)
        return subprocess.run(
            [sys.executable, "-I", str(CLI), str(cp), str(sp), str(out)],
            capture_output=True, text=True,
        )

    def test_cli_success_writes_json(self):
        client, server = simple_flow(rows=[[b"1"]])
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "result.json"
            proc = self._run_cli(client, server, out)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data[0]["rows"], [[b64(b"1")]])

    def test_cli_double_empty_writes_empty_array(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "result.json"
            proc = self._run_cli(b"", b"", out)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(out.read_text()), [])

    def test_cli_failure_keeps_old_output(self):
        client, server = simple_flow()
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "result.json"
            good_client, good_server = simple_flow(rows=[[b"old"]])
            self.assertEqual(self._run_cli(good_client, good_server,
                                           out).returncode, 0)
            old = out.read_text()
            # Now feed an invalid stream (trailing byte).
            proc = self._run_cli(client + b"ZZ", server, out)
            self.assertEqual(proc.returncode, 1)
            self.assertIn("offset", proc.stderr)
            self.assertEqual(out.read_text(), old)

    def test_cli_error_reports_direction_and_offset(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "result.json"
            # Sync is 5 bytes; the bad message starts exactly at byte 5.
            proc = self._run_cli(m.sync() + b"Q\x00\x00\x00\x04",
                                 m.ready(), out)
            self.assertEqual(proc.returncode, 1)
            detail = json.loads(proc.stderr.strip())
            self.assertEqual(detail["direction"], "client")
            self.assertEqual(detail["offset"], 5)

    def test_cli_server_offset_zero_based(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "result.json"
            proc = self._run_cli(m.sync(),
                                 m.ready("T"), out)
            self.assertEqual(proc.returncode, 1)
            detail = json.loads(proc.stderr.strip())
            self.assertEqual(detail["direction"], "server")
            self.assertEqual(detail["offset"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
