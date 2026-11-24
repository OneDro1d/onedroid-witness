"""The signer sidecar (ARCHITECTURE §2, TB4; SPEC §7.1, §7.4): Unix socket only, {predicateType, payload} requests, schema
checks for claim, observation and batch-header payloads, DSSE Ed25519, the signing log, and the operator key-list command
signed by the outgoing and the incoming key."""
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

from claim_witness import dsse, signer, storage as storage_mod
from tests_claim import helpers as h
from tests_claim.helpers import payload_of

CLAIM_T = "https://onedroid.ai/witness/claim/v1"
OBS_T = "https://onedroid.ai/witness/observation/v1"
BATCH_T = "https://onedroid.ai/witness/batch-header/v1"


def claim_statement(core, clock, visibility="public"):
    from claim_witness import ids
    c = {"method": "match.exact", "method_major": 1, "params": {}, "assertion": True, "statement": None}
    pred = {"visibility": "public", "claim": c, "statement": "s", "evidence": [], "method": {"id": "match.exact", "version": "1.0.0",
            "code_sha256": "0" * 64, "runtime": "python3.12"}, "finding": "match", "outcome": "SUPPORTED", "reason": "match",
            "detail": {}, "limits": "Bytes only.", "judgment": None,
            "attempt": {"n": 1, "prior": {"SUPPORTED": 0, "NOT_SUPPORTED": 0, "CANNOT_WITNESS": 0}, "window_days": 30, "scope": "account"},
            "relied_on": [], "submitter": {"account": "acct_a"}, "options_used": {"accept_untrusted": False, "allow_provider": False, "panel": 1},
            "witnessed_at": h.iso(clock()), "witness": {"id": core.witness_id, "key_id": core.key_id, "key_list_seq": 1}}
    return {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "claim", "digest": {"sha256": ids.claim_id(c)}}],
            "predicateType": CLAIM_T, "predicate": pred}


class Core(unittest.TestCase):
    def setUp(self):
        self.clock = h.Clock()
        self.st = storage_mod.MemoryStorage()
        signer.keylist_init(self.st, h.seed(1), "w:k1", "w", clock=self.clock)
        self.core = signer.SignerCore(h.seed(1), "w:k1", "w", self.st, clock=self.clock)

    def test_info(self):
        self.assertEqual(self.core.info(), {"witness_id": "w", "key_id": "w:k1", "key_list_seq": 1,
                                            "public": h.b64(h.public_of(h.seed(1)))})

    def test_signs_a_valid_claim_and_logs_it(self):
        n = len(self.st.signing_log())
        out = self.core.sign(CLAIM_T, claim_statement(self.core, self.clock))
        env = out["envelope"]
        self.assertTrue(dsse.verify(env, {"w:k1": h.public_of(h.seed(1))}))
        log = self.st.signing_log()
        self.assertEqual(len(log), n + 1)
        self.assertEqual(log[-1]["seq"], out["log_seq"])
        self.assertEqual(log[-1]["payload_id"], out["payload_id"])
        self.assertEqual(log[-1]["predicate_type"], CLAIM_T)

    def test_refuses_unknown_predicate_type(self):
        with self.assertRaises(signer.Refused):
            self.core.sign("https://onedroid.ai/witness/key-list/v1", claim_statement(self.core, self.clock))
        with self.assertRaises(signer.Refused):
            self.core.sign("https://example.com/anything", {"x": 1})

    def test_refuses_payloads_failing_schema(self):
        bad = []
        s = claim_statement(self.core, self.clock)
        s["predicate"]["extra"] = 1
        bad.append(s)
        s = claim_statement(self.core, self.clock)
        s["predicate"]["outcome"] = "TRUE"
        bad.append(s)
        s = claim_statement(self.core, self.clock)
        s["predicate"]["detail"] = {"similarity": 0.5}
        bad.append(s)
        s = claim_statement(self.core, self.clock)
        s["predicateType"] = OBS_T
        bad.append(s)
        s = claim_statement(self.core, self.clock)
        s["predicate"]["witness"]["key_id"] = "w:other"
        bad.append(s)
        s = claim_statement(self.core, self.clock)
        s["predicate"]["witnessed_at"] = h.iso(self.clock() - 3600)
        bad.append(s)
        s = claim_statement(self.core, self.clock)
        s["predicate"]["visibility"] = "private"  # a private payload with public fields
        bad.append(s)
        n = len(self.st.signing_log())
        for s in bad:
            with self.assertRaises(signer.Refused, msg=json.dumps(s)[:200]):
                self.core.sign(CLAIM_T, s)
        self.assertEqual(len(self.st.signing_log()), n)

    def test_signs_private_claim_observation_and_batch_header(self):
        s = claim_statement(self.core, self.clock)
        p = s["predicate"]
        s["predicate"] = {k: p[k] for k in ("finding", "outcome", "reason", "method", "limits", "detail", "attempt", "options_used",
                                            "witnessed_at", "witness")}
        s["predicate"].update(visibility="private", body_commitment="1" * 64)
        self.core.sign(CLAIM_T, s)
        obs = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "observation", "digest": {"sha256": "2" * 64}}],
               "predicateType": OBS_T, "predicate": {"visibility": "private", "body_commitment": "2" * 64,
                                                     "fetched_at": h.iso(self.clock()), "fetcher": {"id": "onedroid-fetcher", "version": "1.0.0"}}}
        self.core.sign(OBS_T, obs)
        header = {"witness": "w", "batch_id": "3" * 64, "root": "4" * 64, "size": 10, "opened_at": h.iso(self.clock() - 3600),
                  "closed_at": h.iso(self.clock()), "interval_s": 3600, "key_id": "w:k1"}
        out = self.core.sign(BATCH_T, header)
        self.assertIn("sig", out)
        types = [r["predicate_type"] for r in self.st.signing_log()]
        self.assertEqual(types[-3:], [CLAIM_T, OBS_T, BATCH_T])


class Socket(unittest.TestCase):
    def test_round_trip_over_unix_socket_only(self):
        clock = h.Clock()
        st = storage_mod.MemoryStorage()
        signer.keylist_init(st, h.seed(1), "w:k1", "w", clock=clock)
        core = signer.SignerCore(h.seed(1), "w:k1", "w", st, clock=clock)
        d = tempfile.mkdtemp(prefix="cw-sock-")
        path = os.path.join(d, "signer.sock")
        srv = signer.make_socket_server(path, core)
        self.assertEqual(srv.socket.family, socket.AF_UNIX)
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), oct(0o660))
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            client = signer.SocketSignerClient(path)
            self.assertEqual(client.info()["key_id"], "w:k1")
            out = client.sign(CLAIM_T, claim_statement(core, clock))
            self.assertTrue(dsse.verify(out["envelope"], {"w:k1": h.public_of(h.seed(1))}))
            with self.assertRaises(signer.Refused):
                client.sign("https://example.com/x", {"a": 1})
        finally:
            srv.shutdown()
            srv.server_close()

    def test_socket_path_must_come_from_env_and_be_absolute(self):
        with self.assertRaises(SystemExit):
            signer.socket_path_from_env({})
        with self.assertRaises(SystemExit):
            signer.socket_path_from_env({"WITNESS_SIGNER_SOCKET": "relative.sock"})
        with self.assertRaises(SystemExit):
            signer.socket_path_from_env({"WITNESS_SIGNER_SOCKET": "127.0.0.1:9000"})
        self.assertEqual(signer.socket_path_from_env({"WITNESS_SIGNER_SOCKET": "/run/witness/signer.sock"}), "/run/witness/signer.sock")

    def test_no_tcp_listener_in_signer_module(self):
        src = (h.ROOT / "claim_witness" / "signer.py").read_text()
        self.assertNotIn("AF_INET", src)
        self.assertNotIn("TCPServer", src)
        self.assertNotIn("HTTPServer", src)


class KeyLists(unittest.TestCase):
    def test_init_then_rotate_signed_by_outgoing_and_incoming(self):
        clock = h.Clock()
        st = storage_mod.MemoryStorage()
        env1 = signer.keylist_init(st, h.seed(1), "w:k1", "w", clock=clock)
        kl1 = payload_of(env1)["predicate"]
        self.assertEqual(kl1["seq"], 1)
        self.assertEqual(kl1["witness"], "w")
        self.assertEqual(kl1["keys"], [{"key_id": "w:k1", "alg": "ed25519", "public": h.b64(h.public_of(h.seed(1))),
                                        "valid_from": h.iso(clock()), "valid_to": None, "revoked_at": None, "revoke_reason": None}])
        self.assertEqual(kl1["sealers"], [])
        self.assertEqual(kl1["batch_interval_s"], 3600)
        with self.assertRaises(SystemExit):
            signer.keylist_init(st, h.seed(1), "w:k1", "w", clock=clock)
        clock.advance(86400)
        env2 = signer.keylist_rotate(st, h.seed(1), "w:k1", h.seed(2), "w:k2", "w", clock=clock)
        kl2 = payload_of(env2)["predicate"]
        self.assertEqual(kl2["seq"], 2)
        by = {k["key_id"]: k for k in kl2["keys"]}
        self.assertEqual(by["w:k1"]["valid_to"], h.iso(clock()))
        self.assertIsNone(by["w:k2"]["valid_to"])
        self.assertEqual({s["keyid"] for s in env2["signatures"]}, {"w:k1", "w:k2"})
        self.assertTrue(dsse.verify(env2, {"w:k1": h.public_of(h.seed(1))}, keyid="w:k1"))
        self.assertTrue(dsse.verify(env2, {"w:k2": h.public_of(h.seed(2))}, keyid="w:k2"))
        self.assertEqual(st.get_key_list(2), env2)
        self.assertEqual(st.latest_key_list()["seq"], 2)
        types = [r["predicate_type"] for r in st.signing_log()]
        self.assertEqual(types, ["https://onedroid.ai/witness/key-list/v1"] * 2)

    def test_rotate_refuses_wrong_outgoing_key_and_can_revoke(self):
        clock = h.Clock()
        st = storage_mod.MemoryStorage()
        signer.keylist_init(st, h.seed(1), "w:k1", "w", clock=clock)
        with self.assertRaises(SystemExit):
            signer.keylist_rotate(st, h.seed(9), "w:k1", h.seed(2), "w:k2", "w", clock=clock)
        env = signer.keylist_rotate(st, h.seed(1), "w:k1", h.seed(2), "w:k2", "w", clock=clock, revoke_reason="key exposed")
        by = {k["key_id"]: k for k in payload_of(env)["predicate"]["keys"]}
        self.assertEqual(by["w:k1"]["revoked_at"], h.iso(clock()))
        self.assertEqual(by["w:k1"]["revoke_reason"], "key exposed")

    def test_core_refuses_to_sign_with_a_key_not_current(self):
        clock = h.Clock()
        st = storage_mod.MemoryStorage()
        signer.keylist_init(st, h.seed(1), "w:k1", "w", clock=clock)
        signer.keylist_rotate(st, h.seed(1), "w:k1", h.seed(2), "w:k2", "w", clock=clock)
        with self.assertRaises(SystemExit):
            signer.SignerCore(h.seed(1), "w:k1", "w", st, clock=clock)
        core2 = signer.SignerCore(h.seed(2), "w:k2", "w", st, clock=clock)
        self.assertEqual(core2.info()["key_list_seq"], 2)

    def test_operator_cli_init_and_rotate(self):
        d = pathlib.Path(tempfile.mkdtemp(prefix="cw-cli-"))
        k1, k2 = d / "k1", d / "k2"
        k1.write_text(h.b64(h.seed(1)) + "\n")
        k2.write_text(h.b64(h.seed(2)) + "\n")
        db = d / "mem.json"
        env = dict(os.environ, WITNESS_STORAGE_FILE=str(db), WITNESS_ID="w", PYTHONPATH=str(h.ROOT))
        env.pop("WITNESS_DATABASE_URL", None)
        r = subprocess.run([sys.executable, "-m", "claim_witness", "signer", "keylist", "init", "--key-file", str(k1), "--key-id", "w:k1"],
                           env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = subprocess.run([sys.executable, "-m", "claim_witness", "signer", "keylist", "rotate", "--outgoing-key-file", str(k1),
                            "--outgoing-key-id", "w:k1", "--incoming-key-file", str(k2), "--incoming-key-id", "w:k2"],
                           env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("seq 2", r.stdout)
        self.assertNotIn(h.b64(h.seed(1)), r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
