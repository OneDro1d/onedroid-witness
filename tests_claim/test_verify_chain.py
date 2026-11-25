"""witness-verify reads the base-sepolia anchor transaction of a seal when given --rpc (BD21, SPEC §6 step 4-5, README_CLAIM 82).

The real vector is public chain data read once from https://sepolia.base.org (tests_claim/fixtures/base-sepolia/): tx
0x7cf24d51... in block 63379082, from armarium's notary account to 0x0, input the UTF-8 JSON datablock
{"correlationId", "previousChunkBlockId", "chunkData", "mode": "hash", "payload": {"label", "over"}}. Every test runs with no
network: a fake JSON-RPC server on 127.0.0.1 serves those two answers (or a changed copy of them).
"""
import copy
import http.server
import io
import json
import pathlib
import socket
import threading
import unittest

from claim_witness import verify
from tests_claim import helpers as h
from tests_claim.test_record_methods import Base

FIX = pathlib.Path(__file__).parent / "fixtures" / "base-sepolia"
TX = json.loads((FIX / "eth_getTransactionByHash-0x7cf24d51.json").read_text())["result"]
BLOCK = json.loads((FIX / "eth_getBlockByNumber-63379082.json").read_text())["result"]
TX_HASH = "0x7cf24d518f6d3bd6f6940aa68e4e1c3503fbade13bb368521174ff27e8346665"
OVER = "sha256:baa5bb1dace420fdc73784ddfe514a2a222f186b824a195cab9e4f8a7560adf1"
SENDER = "0x9c26a33d30275541afef12e5787eae76bca37aff"
BLOCK_NO = 63379082
BLOCK_TIME = "2026-11-25T09:08:05Z"
ANCHOR = {"chain": "base-sepolia", "state": "landed", "tx_hash": TX_HASH, "block": BLOCK_NO, "block_time": BLOCK_TIME, "final": True}


def datablock(over=OVER, mode="hash"):
    return json.dumps({"correlationId": "249fe7263de9f5d0339ebff5a3957c4c", "previousChunkBlockId": "0", "chunkData": "",
                       "mode": mode, "payload": {"label": "claim-witness/batch/1", "over": over}}, separators=(",", ":"))


class FakeRpc:
    """A JSON-RPC server on 127.0.0.1 answering eth_getTransactionByHash and eth_getBlockByNumber from dicts."""

    def __init__(self):
        self.txs, self.blocks, self.calls, self.error = {}, {}, [], None
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.calls.append((req["method"], req["params"]))
                if outer.error == "http":
                    self.send_response(503)
                    self.end_headers()
                    return
                if outer.error == "rpc":
                    body = {"jsonrpc": "2.0", "id": req["id"], "error": {"code": -32000, "message": "boom"}}
                elif outer.error == "junk":
                    body = None
                elif req["method"] == "eth_getTransactionByHash":
                    body = {"jsonrpc": "2.0", "id": req["id"], "result": outer.txs.get(req["params"][0])}
                elif req["method"] == "eth_getBlockByNumber":
                    body = {"jsonrpc": "2.0", "id": req["id"], "result": outer.blocks.get(req["params"][0])}
                else:
                    body = {"jsonrpc": "2.0", "id": req["id"], "error": {"code": -32601, "message": "no such method"}}
                data = b"<html>not json</html>" if body is None else json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def serve(self, tx_hash, number, over, timestamp, sender=SENDER, to="0x" + "0" * 40, mode="hash", raw_input=None):
        tx = dict(TX, hash=tx_hash, blockNumber=hex(number), to=to, **{"from": sender})
        tx["input"] = raw_input if raw_input is not None else "0x" + datablock(over, mode).encode().hex()
        self.txs[tx_hash] = tx
        self.blocks[hex(number)] = dict(BLOCK, number=hex(number), timestamp=hex(timestamp), hash=tx["blockHash"])

    def serve_real(self):
        self.txs[TX_HASH], self.blocks[hex(BLOCK_NO)] = copy.deepcopy(TX), copy.deepcopy(BLOCK)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def dead_url():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


class RealVector(unittest.TestCase):
    def setUp(self):
        self.rpc = FakeRpc()
        self.rpc.serve_real()
        self.addCleanup(self.rpc.close)

    def check(self, anchor=ANCHOR, over=OVER, sealers=None):
        return verify.check_anchor_tx(self.rpc.url, anchor, over, sealers)

    def test_the_fixture_is_the_measured_shape(self):
        self.assertEqual(TX["from"], SENDER)
        self.assertEqual(TX["to"], "0x" + "0" * 40)
        self.assertEqual(int(TX["blockNumber"], 16), BLOCK_NO)
        self.assertEqual(len(bytes.fromhex(TX["input"][2:])), 233)
        self.assertEqual(json.loads(bytes.fromhex(TX["input"][2:]))["payload"]["over"], OVER)

    def test_the_real_transaction_passes_and_the_line_names_chain_tx_block_and_sender(self):
        ok, text = self.check()
        self.assertTrue(ok, text)
        for part in ("base-sepolia", TX_HASH, str(BLOCK_NO), SENDER):
            self.assertIn(part, text)

    def test_with_no_sealer_list_the_pass_line_says_the_sender_was_not_checked(self):
        ok, text = self.check(sealers=None)
        self.assertTrue(ok, text)
        self.assertIn("not checked against a sealer list", text)

    def test_a_different_over_fails_by_name(self):
        ok, text = self.check(over="sha256:" + "0" * 64)
        self.assertFalse(ok)
        self.assertIn("different over", text)

    def test_a_different_block_fails_by_name(self):
        ok, text = self.check(anchor=dict(ANCHOR, block=BLOCK_NO + 1))
        self.assertFalse(ok)
        self.assertIn("block mismatch", text)

    def test_a_block_time_one_second_off_fails_by_name(self):
        ok, text = self.check(anchor=dict(ANCHOR, block_time="2026-11-25T09:08:06Z"))
        self.assertFalse(ok)
        self.assertIn("time mismatch", text)

    def test_an_unknown_transaction_is_not_found(self):
        ok, text = self.check(anchor=dict(ANCHOR, tx_hash="0x" + "ab" * 32))
        self.assertFalse(ok)
        self.assertIn("not found", text)

    def test_a_transaction_to_another_address_fails_by_name(self):
        self.rpc.serve(TX_HASH, BLOCK_NO, OVER, 1795597685, to="0x" + "1" * 40)
        ok, text = self.check()
        self.assertFalse(ok)
        self.assertIn("not to 0x0", text)

    def test_a_non_hash_mode_datablock_fails_by_name(self):
        self.rpc.serve(TX_HASH, BLOCK_NO, OVER, 1795597685, mode="chunk")
        ok, text = self.check()
        self.assertFalse(ok)
        self.assertIn("not a hash-mode datablock", text)

    def test_input_that_is_not_json_fails_by_name(self):
        for raw in ("0x" + b"hello".hex(), "0xff", "0x"):
            self.rpc.serve(TX_HASH, BLOCK_NO, OVER, 1795597685, raw_input=raw)
            ok, text = self.check()
            self.assertFalse(ok, raw)
            self.assertIn("not a hash-mode datablock", text)

    def test_the_sender_must_be_a_listed_sealer_at_the_block_time(self):
        listed = [{"chain": "base-sepolia", "address": SENDER.upper().replace("0X", "0x"), "valid_from": "2026-11-01T00:00:00Z",
                   "valid_to": None}]
        ok, text = self.check(sealers=listed)
        self.assertTrue(ok, text)
        self.assertNotIn("not checked", text)
        self.assertIn("sealer", text)

    def test_a_sender_not_among_the_sealers_fails(self):
        other = [{"chain": "base-sepolia", "address": "0x" + "2" * 40, "valid_from": "2026-11-01T00:00:00Z", "valid_to": None}]
        ok, text = self.check(sealers=other)
        self.assertFalse(ok)
        self.assertIn("sender", text)
        self.assertIn("not a sealer", text)

    def test_a_sealer_valid_only_after_the_block_time_fails(self):
        late = [{"chain": "base-sepolia", "address": SENDER, "valid_from": "2026-11-26T00:00:00Z", "valid_to": None}]
        ok, text = self.check(sealers=late)
        self.assertFalse(ok)
        self.assertIn("not a sealer", text)

    def test_a_sealer_that_ended_before_the_block_time_fails(self):
        gone = [{"chain": "base-sepolia", "address": SENDER, "valid_from": "2026-11-01T00:00:00Z", "valid_to": "2026-11-25T09:08:04Z"}]
        ok, text = self.check(sealers=gone)
        self.assertFalse(ok)

    def test_the_rpc_error_unreachable_and_junk_answers_are_failures_naming_the_rpc(self):
        for mode in ("rpc", "http", "junk"):
            self.rpc.error = mode
            ok, text = self.check()
            self.assertFalse(ok, mode)
            self.assertIn(self.rpc.url, text)
        ok, text = verify.check_anchor_tx(dead_url(), ANCHOR, OVER, None)
        self.assertFalse(ok)
        self.assertIn("127.0.0.1", text)

    def test_sealer_selection_uses_the_key_list_and_the_flag(self):
        self.assertIsNone(verify._sealers_for({"sealers": []}, []))
        self.assertIsNone(verify._sealers_for(None, []))
        kl = {"sealers": [{"chain": "lab-qbft", "address": "0x" + "3" * 40, "valid_from": "x", "valid_to": None},
                          {"chain": "base-sepolia", "address": SENDER, "valid_from": "x", "valid_to": None}]}
        self.assertEqual([s["address"] for s in verify._sealers_for(kl, [])], [SENDER])
        flag = verify._sealers_for({"sealers": []}, ["0x" + "4" * 40])
        self.assertEqual([s["address"] for s in flag], ["0x" + "4" * 40])
        self.assertTrue(verify._sealers_for(kl, ["0x" + "4" * 40]))


class SealedRecord(Base, unittest.TestCase):
    """A record sealed by the test notary (one base-sepolia anchor), checked by the verifier's main()."""

    def setUp(self):
        super().setUp()
        self.rpc = FakeRpc()
        self.addCleanup(self.rpc.close)
        rec = self.sealed_public()
        self.rid = rec["record_id"]
        code, self.seal, _ = self.s.call("GET", f"/v1/records/{self.rid}/seal", key=None)
        self.assertEqual(self.seal["state"], "anchored", self.seal)
        import tempfile
        self.d = pathlib.Path(tempfile.mkdtemp(prefix="cw-chain-"))
        (self.d / "envelope.json").write_text(json.dumps(self.s.storage.get_kept(self.rid)["envelope"]))
        (self.d / "keys.json").write_text(json.dumps(self.s.storage.get_key_list(1)))
        self.write_seal(self.seal)
        self.anchor = self.seal["notary"]["anchors"][0]
        self.over = self.seal["notary"]["over"]

    def write_seal(self, seal):
        (self.d / "seal.json").write_text(json.dumps(seal))

    def serve_anchor(self, anchor=None, **kw):
        a = anchor or self.anchor
        ts = verify._secs(a["block_time"])
        args = dict(tx_hash=a["tx_hash"], number=a["block"], over=self.over, timestamp=ts)
        args.update(kw)
        self.rpc.serve(**args)

    def run_verify(self, *extra):
        buf = io.StringIO()
        code = verify.main(["--envelope", str(self.d / "envelope.json"), "--keys", str(self.d / "keys.json"),
                            "--seal", str(self.d / "seal.json"), *extra], out=buf)
        return code, buf.getvalue()

    def test_without_rpc_the_result_is_unchanged_and_the_skip_names_rpc(self):
        code, text = self.run_verify()
        self.assertEqual(code, 0, text)
        line = [x for x in text.splitlines() if x.startswith("SKIP seal-chain")]
        self.assertEqual(len(line), 1, text)
        self.assertIn("--rpc", line[0])
        self.assertEqual(self.rpc.calls, [])

    def test_with_rpc_a_matching_anchor_transaction_passes(self):
        self.serve_anchor()
        code, text = self.run_verify("--rpc", self.rpc.url)
        self.assertEqual(code, 0, text)
        line = [x for x in text.splitlines() if x.startswith("PASS seal-chain")]
        self.assertEqual(len(line), 1, text)
        for part in ("base-sepolia", self.anchor["tx_hash"], str(self.anchor["block"]), SENDER):
            self.assertIn(part, line[0])
        self.assertNotIn("SKIP seal-chain", text)
        self.assertIn("PASS key-validity", text)

    def test_with_rpc_a_different_over_fails_and_exits_1(self):
        self.serve_anchor(over="sha256:" + "0" * 64)
        code, text = self.run_verify("--rpc", self.rpc.url)
        self.assertEqual(code, 1, text)
        self.assertIn("FAIL seal-chain", text)
        self.assertIn("different over", text)
        self.assertNotIn("PASS seal-chain", text)

    def test_with_rpc_a_block_time_the_chain_does_not_have_fails(self):
        self.serve_anchor(timestamp=verify._secs(self.anchor["block_time"]) + 1)
        code, text = self.run_verify("--rpc", self.rpc.url)
        self.assertEqual(code, 1, text)
        self.assertIn("time mismatch", text)

    def test_with_rpc_an_unknown_transaction_fails(self):
        code, text = self.run_verify("--rpc", self.rpc.url)
        self.assertEqual(code, 1, text)
        self.assertIn("FAIL seal-chain", text)
        self.assertIn("not found", text)

    def test_an_unreachable_rpc_is_a_failure_naming_it_never_a_pass(self):
        url = dead_url()
        code, text = self.run_verify("--rpc", url)
        self.assertEqual(code, 1, text)
        self.assertIn("FAIL seal-chain", text)
        self.assertIn(url, text)
        self.assertNotIn("PASS seal-chain", text)

    def test_an_rpc_that_answers_an_error_is_a_failure(self):
        self.rpc.error = "rpc"
        code, text = self.run_verify("--rpc", self.rpc.url)
        self.assertEqual(code, 1, text)
        self.assertIn("FAIL seal-chain", text)

    def test_the_sealer_flag_accepts_the_sender_and_refuses_another(self):
        self.serve_anchor()
        code, text = self.run_verify("--rpc", self.rpc.url, "--sealer", SENDER)
        self.assertEqual(code, 0, text)
        self.assertNotIn("not checked against a sealer list", text)
        code, text = self.run_verify("--rpc", self.rpc.url, "--sealer", "0x" + "5" * 40, "--sealer", "0x" + "6" * 40)
        self.assertEqual(code, 1, text)
        self.assertIn("not a sealer", text)

    def test_the_default_key_list_names_no_sealers_so_the_sender_is_reported_not_failed(self):
        self.serve_anchor()
        code, text = self.run_verify("--rpc", self.rpc.url)
        self.assertEqual(code, 0, text)
        self.assertIn("not checked against a sealer list", text)

    def test_lab_qbft_is_never_claimed_as_checked_by_the_rpc(self):
        anchors = [dict(self.anchor, chain="lab-qbft")]
        self.write_seal(dict(self.seal, notary=dict(self.seal["notary"], anchors=anchors)))
        code, text = self.run_verify("--rpc", self.rpc.url)
        self.assertEqual(code, 0, text)
        self.assertEqual(self.rpc.calls, [])
        self.assertNotIn("PASS seal-chain", text)
        line = [x for x in text.splitlines() if x.startswith("SKIP seal-chain")]
        self.assertEqual(len(line), 1, text)
        self.assertIn("lab-qbft", line[0])
        self.assertIn("operator's own chain", line[0])

    def test_lab_qbft_beside_a_passing_base_sepolia_anchor_is_a_skip_not_a_fail(self):
        lab = dict(self.anchor, chain="lab-qbft", tx_hash="0x" + "cd" * 32, block=70748)
        self.write_seal(dict(self.seal, notary=dict(self.seal["notary"], anchors=[lab, self.anchor])))
        self.serve_anchor()
        code, text = self.run_verify("--rpc", self.rpc.url)
        self.assertEqual(code, 0, text)
        self.assertIn("PASS seal-chain", text)
        self.assertIn("SKIP seal-chain", text)
        self.assertEqual([c[0] for c in self.rpc.calls].count("eth_getTransactionByHash"), 1)

    def test_only_a_base_sepolia_anchor_that_failed_fails_the_result(self):
        lab = dict(self.anchor, chain="lab-qbft", tx_hash="0x" + "cd" * 32, block=70748)
        self.write_seal(dict(self.seal, notary=dict(self.seal["notary"], anchors=[lab, self.anchor])))
        code, text = self.run_verify("--rpc", self.rpc.url)
        self.assertEqual(code, 1, text)
        self.assertIn("FAIL seal-chain", text)

    def test_the_rpc_flag_changes_nothing_else_in_the_output(self):
        self.serve_anchor()
        _, plain = self.run_verify()
        _, chained = self.run_verify("--rpc", self.rpc.url)
        keep = lambda t: [x for x in t.splitlines() if "seal-chain" not in x]
        self.assertEqual(keep(plain), keep(chained))


if __name__ == "__main__":
    unittest.main()
