"""B3W: the manifest names armarium's real Secrets, ConfigMaps and URLs; migration 005 holds the owners' chains; README has the
B3W decisions; tools/live_armarium_smoke.py exercises the real code paths (here against the real-shaped fakes) within its bounds
and never prints a token. RED first."""
import importlib.util
import io
import json
import re
import unittest

from tests_claim import helpers as h
from tests_claim.fake_armarium_real import CASE, RealNotary, RealObjects
from tests_claim.fake_seal import make_tls
from tests_claim.test_deploy_files import docs, kind_of

TLS = None


def setUpModule():
    global TLS
    TLS = make_tls()


class Manifest(unittest.TestCase):
    def setUp(self):
        self.text = (h.ROOT / "k8s" / "claim-dev.yaml").read_text()
        dep = [d for d in docs(self.text) if kind_of(d) == "Deployment" and "name: claim-witness" in d][0]
        self.api, rest = dep.split('args: ["signer", "serve"]')
        self.volumes = rest.split("      volumes:")[1]

    def env(self, name):
        m = re.search(r"- \{name: %s, value: \"?([^\"}]*)\"?\}" % name, self.api)
        self.assertIsNotNone(m, name)
        return m.group(1)

    def volume(self, name):
        m = re.search(r"(?s)- name: %s\n(.*?)(?=\n        - name: |\Z)" % re.escape(name), self.volumes)
        self.assertIsNotNone(m, name)
        return m.group(1)

    def mount_of(self, volume):
        m = re.search(r"- \{name: %s, mountPath: (\S+), readOnly: true\}" % re.escape(volume), self.api)
        self.assertIsNotNone(m, volume)
        return m.group(1)

    def test_the_urls_and_case_are_written_in(self):
        self.assertEqual(self.env("WITNESS_NOTARY_URL"), "https://armarium-notary.armarium-lab.svc.cluster.local:9000")
        self.assertEqual(self.env("ARMARIUM_URL"), "https://armarium-objects.armarium-objects-dev.svc.cluster.local:9000")
        self.assertEqual(self.env("ARMARIUM_CASE"), CASE)
        self.assertNotIn("ARMARIUM_CHAIN", self.api)
        self.assertNotIn("URL_PLACEHOLDER", self.text)

    def test_real_secret_and_configmap_names(self):
        self.assertRegex(self.volume("notary-token"), r"secretName: armarium-claim-witness\n")
        self.assertRegex(self.volume("armarium-token"), r"secretName: armarium-claim-witness-objects\n")
        self.assertRegex(self.volume("armarium-ca"), r"name: armarium-ca\n")
        self.assertRegex(self.volume("armarium-objects-ca"), r"name: armarium-objects-ca\n")
        for old in ("claim-witness-notary-token", "claim-witness-armarium-token"):
            self.assertNotIn(old, self.text)
        for vol in ("notary-token", "armarium-token", "armarium-ca", "armarium-objects-ca"):
            self.assertIn("optional: true", self.volume(vol), vol)
            self.assertIn("key: token" if "token" in vol else "key: ca.crt", self.volume(vol))

    def test_two_separate_ca_mounts_and_token_mounts(self):
        notary_ca, objects_ca = self.mount_of("armarium-ca"), self.mount_of("armarium-objects-ca")
        self.assertNotEqual(notary_ca, objects_ca)
        self.assertEqual(self.env("WITNESS_NOTARY_CA_FILE"), notary_ca + "/ca.crt")
        self.assertEqual(self.env("ARMARIUM_CA_FILE"), objects_ca + "/ca.crt")
        nt, ot = self.mount_of("notary-token"), self.mount_of("armarium-token")
        self.assertNotEqual(nt, ot)
        self.assertEqual(self.env("WITNESS_NOTARY_TOKEN_FILE"), nt + "/token")
        self.assertEqual(self.env("ARMARIUM_TOKEN_FILE"), ot + "/token")

    def test_placeholders_and_signer_untouched(self):
        self.assertIn("IMAGE_PLACEHOLDER", self.text)
        self.assertIn("IMAGE_DIGEST_PLACEHOLDER", self.text)
        signer = self.text.split('args: ["signer", "serve"]')[1].split("      volumes:")[0]
        for name in ("ARMARIUM", "NOTARY", "armarium"):
            self.assertNotIn(name, signer)
        self.assertEqual([d for d in docs(self.text) if kind_of(d) in ("Secret", "ConfigMap")], [])


class Migration(unittest.TestCase):
    def test_005_holds_the_owners_chains_on_both_backends(self):
        files = sorted((h.ROOT / "claim_witness" / "migrations").glob("005_*.sql"))
        self.assertEqual(len(files), 1)
        sql = files[0].read_text()
        for word in ("ndim_chains", "owner_tag", "claimant_id", "case_id", "state", "attempts", "next_try_at", "last_error"):
            self.assertIn(word, sql)
        self.assertNotRegex(sql, r"(?m)^\s+account\s")  # the account is never a column of this table
        from claim_witness import storage
        for name in ("get_ndim_chain", "put_ndim_chain", "update_ndim_chain", "ndim_chains"):
            self.assertTrue(hasattr(storage.MemoryStorage, name), name)
            self.assertTrue(hasattr(storage.Storage, name), name)
        from claim_witness import pg
        for name in ("get_ndim_chain", "put_ndim_chain", "update_ndim_chain", "ndim_chains"):
            self.assertTrue(hasattr(pg.PostgresStorage, name), name)

    def test_memory_storage_round_trip(self):
        from claim_witness import storage
        st = storage.MemoryStorage()
        row = {"owner_tag": "a" * 64, "case_id": CASE, "claimant_id": None, "state": "pending", "attempts": 0,
               "next_try_at": 0, "last_error": None, "created_at": 1, "updated_at": 1}
        st.put_ndim_chain(row)
        with self.assertRaises(storage.Conflict):
            st.put_ndim_chain(row)
        st.update_ndim_chain("a" * 64, claimant_id="7" * 32, state="ready")
        self.assertEqual(st.get_ndim_chain("a" * 64)["claimant_id"], "7" * 32)
        self.assertEqual([r["state"] for r in st.ndim_chains()], ["ready"])
        self.assertIsNone(st.get_ndim_chain("b" * 64))


class Readme(unittest.TestCase):
    def test_b3w_decisions(self):
        text = (h.ROOT / "README_CLAIM.md").read_text()
        self.assertIn("### Builder decisions, B3W", text)
        part = text.split("### Builder decisions, B3W", 1)[1]
        for word in ("HMAC", "claimant", "DELETE", "final", "ARMARIUM_CASE", "armarium-objects-ca", "label"):
            self.assertIn(word, part, word)
        self.assertNotIn("ARMARIUM_CHAIN", part.replace("ARMARIUM_CHAIN is gone", ""))


class Smoke(unittest.TestCase):
    def load(self):
        spec = importlib.util.spec_from_file_location("live_armarium_smoke", h.ROOT / "tools" / "live_armarium_smoke.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_runs_the_real_paths_within_its_bounds_and_prints_no_token(self):
        smoke = self.load()
        objs, notary = RealObjects(TLS), RealNotary(TLS)
        try:
            env = {"ARMARIUM_URL": objs.url, "ARMARIUM_TOKEN_FILE": objs.token_file, "ARMARIUM_CA_FILE": objs.ca_file,
                   "ARMARIUM_CASE": CASE, "WITNESS_NOTARY_URL": notary.url, "WITNESS_NOTARY_TOKEN_FILE": notary.token_file,
                   "WITNESS_NOTARY_CA_FILE": notary.ca_file}
            buf = io.StringIO()
            res = smoke.run(env, out=buf)
        finally:
            objs.close()
            notary.close()
        self.assertTrue(res["ok"], res)
        self.assertEqual(len(objs.calls("POST", "claimant")), 1)
        obj_calls = [r for r in objs.calls(kind="object")]
        self.assertLessEqual(len(obj_calls), 6)
        self.assertEqual([r["method"] for r in obj_calls], ["POST", "PUT", "GET", "DELETE", "GET"])
        seals = [r for r in notary.requests if r["path"] == "/notary/v1/seals"]
        self.assertEqual(len(seals), 1)
        self.assertEqual(len([r for r in notary.requests if r["path"] == "/notary/v1/verify"]), 1)
        self.assertEqual(res["delete"]["dek"], "deleted")
        self.assertEqual(res["after_delete_status"], 410)
        self.assertRegex(res["claimant_id"], r"^[0-9a-f]{32}$")
        self.assertEqual({a["chain"] for a in res["seal"]["anchors"]}, {"lab-qbft", "base-sepolia"})
        self.assertEqual(res["verify"]["status"], 200)
        out = buf.getvalue() + json.dumps(res)
        self.assertNotIn(objs.TOKEN, out)
        self.assertNotIn(notary.TOKEN, out)
        self.assertIn(res["claimant_id"], out)

    def test_refuses_to_run_without_the_settings(self):
        smoke = self.load()
        res = smoke.run({}, out=io.StringIO())
        self.assertFalse(res["ok"])


if __name__ == "__main__":
    unittest.main()
