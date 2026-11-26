"""witness-verify (SPEC §6 steps 1-3, 5 unsealed, 6 for pure-Python methods, 7; TS-12a): an envelope plus key list verifies
offline, a flipped byte fails by name, the pure-Python Ed25519 path agrees with `cryptography`."""
import base64
import copy
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from claim_witness import tarball, verify
from tests_claim import helpers as h
from tests_claim.helpers import claim, obj_item, request


def run_verify(*args):
    """verify.main with captured output: (exit code, text)."""
    buf = io.StringIO()
    code = verify.main([str(a) for a in args], out=buf)
    return code, buf.getvalue()


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = h.Stack()
        cls.dir = pathlib.Path(tempfile.mkdtemp(prefix="cw-verify-"))
        code, wk, _ = cls.s.call("GET", "/.well-known/witness.json", key=None)
        (cls.dir / "keys.json").write_text(json.dumps(wk["key_list"]))
        cls.agent_seed = h.seed(30)
        code, reg, _ = cls.s.call("POST", "/v1/agent-keys", {"public_key": h.b64(h.public_of(cls.agent_seed))})
        cls.agent_key = {"agent_key_id": reg["agent_key_id"], "agent": reg["agent"], "public_key": h.b64(h.public_of(cls.agent_seed))}
        (cls.dir / "agent_key.json").write_text(json.dumps(cls.agent_key))
        cls.source = b"The witness is not a judge of truth. It signs one answer."
        (cls.dir / "source.txt").write_bytes(cls.source)
        c = claim("quote.in-source", {"quote": "not a judge of truth"})
        ev = [obj_item("source", cls.source, name="source.txt")]
        b = request(c, ev, "public")
        b["agent"] = h.agent_block(cls.agent_seed, reg["agent_key_id"], "witness:test", c, ev, "nonce-verify-0001", h.iso(cls.s.clock()))
        code, cls.public, _ = cls.s.witness_call(b)
        assert code == 200, cls.public
        (cls.dir / "public.json").write_text(json.dumps(cls.public))
        b = request(c, ev, "private")
        b["agent"] = h.agent_block(cls.agent_seed, reg["agent_key_id"], "witness:test", c, ev, "nonce-verify-0002", h.iso(cls.s.clock()))
        code, cls.private, _ = cls.s.witness_call(b)
        assert code == 200, cls.private
        (cls.dir / "private.json").write_text(json.dumps({"envelope": cls.private["envelope"], "seal": cls.private["seal"]}))
        (cls.dir / "disclosure.json").write_text(json.dumps(cls.private["disclosure"]))
        cls.tar = cls.dir / f"witness-methods-{tarball.library_version()}.tar.gz"
        cls.tar.write_bytes(tarball.build_methods_tarball())

    @classmethod
    def tearDownClass(cls):
        cls.s.close()

    def write(self, name, obj):
        p = self.dir / name
        p.write_text(json.dumps(obj))
        return p


class PublicRecord(Fixture):
    def test_envelope_and_key_list_pass(self):
        code, out = run_verify("--envelope", self.dir / "public.json", "--keys", self.dir / "keys.json")
        self.assertEqual(code, 0, out)
        for name in ("key-list", "signature", "payload-canonical", "record-id", "claim-id", "key-validity"):
            self.assertIn(f"PASS {name}", out)
        self.assertIn("SKIP seal", out)
        self.assertIn(self.public["record_id"], out)

    def test_expected_record_id(self):
        code, out = run_verify("--envelope", self.dir / "public.json", "--keys", self.dir / "keys.json", "--record-id", self.public["record_id"])
        self.assertEqual(code, 0, out)
        code, out = run_verify("--envelope", self.dir / "public.json", "--keys", self.dir / "keys.json", "--record-id", "0" * 64)
        self.assertNotEqual(code, 0)
        self.assertIn("FAIL record-id", out)

    def test_flipped_payload_byte_fails(self):
        env = copy.deepcopy(self.public["envelope"])
        raw = bytearray(base64.b64decode(env["payload"]))
        i = raw.index(b"SUPPORTED")
        raw[i] = ord("X")
        env["payload"] = base64.b64encode(bytes(raw)).decode()
        code, out = run_verify("--envelope", self.write("flip.json", env), "--keys", self.dir / "keys.json")
        self.assertEqual(code, 1, out)
        self.assertIn("FAIL signature", out)

    def test_flipped_signature_byte_fails(self):
        env = copy.deepcopy(self.public["envelope"])
        sig = bytearray(base64.b64decode(env["signatures"][0]["sig"]))
        sig[5] ^= 1
        env["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()
        code, out = run_verify("--envelope", self.write("flipsig.json", env), "--keys", self.dir / "keys.json")
        self.assertEqual(code, 1)
        self.assertIn("FAIL signature", out)

    def test_flipped_key_list_fails(self):
        kl = json.loads((self.dir / "keys.json").read_text())
        raw = bytearray(base64.b64decode(kl["payload"]))
        raw[-3] ^= 1
        kl["payload"] = base64.b64encode(bytes(raw)).decode()
        code, out = run_verify("--envelope", self.dir / "public.json", "--keys", self.write("badkeys.json", kl))
        self.assertEqual(code, 1)
        self.assertIn("FAIL key-list", out)

    def test_wrong_key_in_trust_list_fails(self):
        from claim_witness import signer, storage as storage_mod
        st = storage_mod.MemoryStorage()
        other = signer.keylist_init(st, h.seed(77), "witness:test:2026a", "witness:test", clock=h.Clock())
        code, out = run_verify("--envelope", self.dir / "public.json", "--trust", self.write("trust.json", other))
        self.assertEqual(code, 1)
        self.assertIn("FAIL signature", out)

    def test_agent_signature(self):
        code, out = run_verify("--envelope", self.dir / "public.json", "--keys", self.dir / "keys.json", "--agent-key", self.dir / "agent_key.json")
        self.assertEqual(code, 0, out)
        self.assertIn("PASS agent-signature", out)
        wrong = dict(self.agent_key, public_key=h.b64(h.public_of(h.seed(31))))
        code, out = run_verify("--envelope", self.dir / "public.json", "--keys", self.dir / "keys.json", "--agent-key", self.write("wrong_agent.json", wrong))
        self.assertEqual(code, 1)
        self.assertIn("FAIL agent-signature", out)

    def test_method_rerun_from_tarball(self):
        code, out = run_verify("--envelope", self.dir / "public.json", "--keys", self.dir / "keys.json", "--methods", self.tar,
                               "--evidence", self.dir / "source.txt")
        self.assertEqual(code, 0, out)
        self.assertIn("PASS methods-tarball", out)
        self.assertIn("PASS bundle-files", out)
        self.assertIn("PASS method-rerun", out)

    def test_method_rerun_detects_a_wrong_file(self):
        bad = self.dir / "other.txt"
        bad.write_bytes(b"different")
        code, out = run_verify("--envelope", self.dir / "public.json", "--keys", self.dir / "keys.json", "--methods", self.tar,
                               "--evidence", bad)
        self.assertEqual(code, 1)
        self.assertIn("FAIL bundle-files", out)

    # CLI fixes (found while writing the user guide, 26 Nov): --help exits 0, and --evidence takes a folder of files
    def test_help_exits_zero(self):
        code, _ = run_verify("--help")
        self.assertEqual(code, 0)
        code, _ = run_verify("--no-such-flag")
        self.assertEqual(code, 2)

    def test_evidence_folder_is_read_like_a_bundles_evidence(self):
        d = self.dir / "evidence-folder"
        d.mkdir(exist_ok=True)
        (d / "source.txt").write_bytes(self.source)
        code, out = run_verify("--envelope", self.dir / "public.json", "--keys", self.dir / "keys.json", "--methods", self.tar,
                               "--evidence", d)
        self.assertEqual(code, 0, out)
        self.assertIn("PASS bundle-files", out)
        self.assertIn("PASS method-rerun", out)

    def test_missing_evidence_path_is_a_message_not_a_traceback(self):
        err = io.StringIO()
        real, sys.stderr = sys.stderr, err
        try:
            code, out = run_verify("--envelope", self.dir / "public.json", "--keys", self.dir / "keys.json",
                                   "--evidence", self.dir / "no-such-file.txt")
        finally:
            sys.stderr = real
        self.assertEqual(code, 2, out)
        self.assertIn("witness-verify: cannot read input", err.getvalue())

    def test_tampered_tarball_fails(self):
        t = self.dir / "tampered.tar.gz"
        t.write_bytes(self.tar.read_bytes() + b"\x00")
        code, out = run_verify("--envelope", self.dir / "public.json", "--keys", self.dir / "keys.json", "--methods", t,
                               "--evidence", self.dir / "source.txt")
        self.assertEqual(code, 1)
        self.assertIn("FAIL methods-tarball", out)

    def test_bundle_directory(self):
        b = self.dir / "bundle"
        (b / "evidence").mkdir(parents=True, exist_ok=True)
        (b / "envelope.json").write_text(json.dumps(self.public["envelope"]))
        (b / "keys.json").write_text((self.dir / "keys.json").read_text())
        (b / "agent_key.json").write_text(json.dumps(self.agent_key))
        (b / "evidence" / h.sha(self.source)).write_bytes(self.source)
        (b / self.tar.name).write_bytes(self.tar.read_bytes())
        code, out = run_verify("--bundle", b)
        self.assertEqual(code, 0, out)
        self.assertIn("PASS method-rerun", out)
        self.assertIn("PASS agent-signature", out)

    def test_runs_as_a_module_with_stdlib_only(self):
        env = dict(os.environ, PYTHONPATH=str(h.ROOT), WITNESS_VERIFY_PURE="1")
        r = subprocess.run([sys.executable, "-I", "-c",
                            "import sys; sys.path.insert(0, %r); import runpy; sys.argv=['verify','--envelope',%r,'--keys',%r];"
                            " runpy.run_module('claim_witness.verify', run_name='__main__')" % (str(h.ROOT), str(self.dir / "public.json"),
                                                                                                  str(self.dir / "keys.json"))],
                           capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("ed25519: pure-python", r.stdout)

    def test_verify_module_imports_only_the_standard_library(self):
        import ast
        tree = ast.parse((h.ROOT / "claim_witness" / "verify.py").read_text())
        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0, "verify.py must not import from the package")
                mods.add(node.module.split(".")[0])
        allowed = set(sys.stdlib_module_names) | {"cryptography"}
        self.assertEqual(mods - allowed, set())


class PrivateRecord(Fixture):
    def test_without_disclosure_commitments_are_skipped(self):
        code, out = run_verify("--envelope", self.dir / "private.json", "--keys", self.dir / "keys.json")
        self.assertEqual(code, 0, out)
        self.assertIn("SKIP claim-id", out)

    def test_with_disclosure_commitments_and_agent_verify(self):
        code, out = run_verify("--envelope", self.dir / "private.json", "--keys", self.dir / "keys.json", "--disclosure",
                               self.dir / "disclosure.json", "--agent-key", self.dir / "agent_key.json", "--methods", self.tar,
                               "--evidence", self.dir / "source.txt")
        self.assertEqual(code, 0, out)
        for name in ("claim-commitment", "body-commitment", "agent-signature", "method-rerun"):
            self.assertIn(f"PASS {name}", out)

    def test_tampered_disclosure_fails(self):
        d = copy.deepcopy(self.private["disclosure"])
        d["body"]["statement"] = d["body"]["statement"].replace("contains", "lacks")
        code, out = run_verify("--envelope", self.dir / "private.json", "--keys", self.dir / "keys.json", "--disclosure",
                               self.write("bad_disclosure.json", d))
        self.assertEqual(code, 1)
        self.assertIn("FAIL body-commitment", out)
        d = copy.deepcopy(self.private["disclosure"])
        d["salt"] = h.b64(bytes(16)).replace("+", "-").replace("/", "_").rstrip("=")
        code, out = run_verify("--envelope", self.dir / "private.json", "--keys", self.dir / "keys.json", "--disclosure",
                               self.write("bad_salt.json", d))
        self.assertEqual(code, 1)
        self.assertIn("FAIL claim-commitment", out)


class KeyValidity(unittest.TestCase):
    def test_revoked_key_fails_an_unsealed_record(self):
        from claim_witness import signer
        s = h.Stack()
        try:
            code, out, _ = s.witness_call(h.exact_request(b"rev", b"rev"))
            env2 = signer.keylist_rotate(s.storage, s.seed, s.key_id, h.seed(2), "witness:test:2026b", "witness:test", clock=s.clock,
                                         revoke_reason="exposed")
            d = pathlib.Path(s.tmp)
            (d / "env.json").write_text(json.dumps(out))
            (d / "k2.json").write_text(json.dumps(env2))
            code, text = run_verify("--envelope", d / "env.json", "--keys", d / "k2.json")
            self.assertEqual(code, 1, text)
            self.assertIn("FAIL key-validity", text)
        finally:
            s.close()


class PureEd25519(unittest.TestCase):
    def test_pure_verify_agrees_with_cryptography(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        for i in range(3):
            sk = Ed25519PrivateKey.from_private_bytes(h.seed(i))
            msg = b"message %d" % i
            sig = sk.sign(msg)
            pub = h.public_of(h.seed(i))
            self.assertTrue(verify.ed25519_verify_pure(pub, sig, msg))
            self.assertFalse(verify.ed25519_verify_pure(pub, sig, msg + b"x"))
            bad = bytearray(sig)
            bad[0] ^= 1
            self.assertFalse(verify.ed25519_verify_pure(pub, bytes(bad), msg))
            self.assertEqual(verify.ed25519_sign_pure(h.seed(i), msg), sig)
            self.assertEqual(verify.ed25519_public_pure(h.seed(i)), pub)

    def test_rfc8032_test_vector_1(self):
        sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        self.assertEqual(verify.ed25519_public_pure(sk), pk)
        self.assertEqual(verify.ed25519_sign_pure(sk, b""), sig)
        self.assertTrue(verify.ed25519_verify_pure(pk, sig, b""))


if __name__ == "__main__":
    unittest.main()
