"""RFC 8785 canonical JSON with integers only (BD9), and the ids and commitments of SPEC §2.0 and §2.6 (VR-3)."""
import hashlib
import unittest

from claim_witness import ids, jcs


class CanonicalJSON(unittest.TestCase):
    def test_keys_sorted_by_utf16_code_units(self):
        # RFC 8785 §3.2.3: U+20AC (0x20AC) sorts after U+1F600 (surrogates 0xD83D...) is false; 0x20AC < 0xD83D
        obj = {"\U0001F600": 1, "€": 2, "a": 3, "B": 4, "": 5}
        self.assertEqual(jcs.canonical(obj), '{"":5,"B":4,"a":3,"€":2,"😀":1}'.encode("utf-8"))

    def test_string_escapes(self):
        self.assertEqual(jcs.canonical("a\"b\\c\n\t\x01\x1f/é"), b'"a\\"b\\\\c\\n\\t\\u0001\\u001f/\xc3\xa9"')

    def test_no_whitespace_and_literals(self):
        self.assertEqual(jcs.canonical({"b": [True, False, None], "a": {"x": -7}}), b'{"a":{"x":-7},"b":[true,false,null]}')

    def test_floats_refused(self):
        for bad in (1.5, {"a": 0.0}, [float("nan")]):
            with self.assertRaises(jcs.CanonicalError):
                jcs.canonical(bad)

    def test_integers_outside_ijson_range_refused(self):
        jcs.canonical(2 ** 53 - 1)
        with self.assertRaises(jcs.CanonicalError):
            jcs.canonical(2 ** 53)

    def test_non_string_keys_refused(self):
        with self.assertRaises(jcs.CanonicalError):
            jcs.canonical({1: "a"})

    def test_strict_loads_refuses_floats_and_duplicate_keys(self):
        self.assertEqual(jcs.loads_strict(b'{"a":1}'), {"a": 1})
        for bad in (b'{"a":1.0}', b'{"a":1,"a":2}', b'{"a":1e3}', b"\xff"):
            with self.assertRaises(jcs.CanonicalError):
                jcs.loads_strict(bad)

    def test_is_canonical(self):
        self.assertTrue(jcs.is_canonical(b'{"a":1,"b":2}'))
        self.assertFalse(jcs.is_canonical(b'{"b":2,"a":1}'))
        self.assertFalse(jcs.is_canonical(b'{"a": 1}'))


class Ids(unittest.TestCase):
    CLAIM = {"method": "match.exact", "method_major": 1, "params": {}, "assertion": True, "statement": None}

    def test_claim_id_is_sha256_of_canonical_claim(self):
        want = hashlib.sha256(jcs.canonical(self.CLAIM)).hexdigest()
        self.assertEqual(ids.claim_id(self.CLAIM), want)
        self.assertRegex(want, r"^[0-9a-f]{64}$")

    def test_record_id_is_sha256_of_payload_and_leaf_has_prefix(self):
        payload = jcs.canonical({"x": 1})
        self.assertEqual(ids.record_id(payload), hashlib.sha256(payload).hexdigest())
        self.assertEqual(ids.leaf_hash(payload), hashlib.sha256(b"\x00" + payload).hexdigest())
        self.assertNotEqual(ids.record_id(payload), ids.leaf_hash(payload))

    def test_commitments_exactly_as_written(self):
        salt = bytes(range(16))
        body = {"visibility": "private", "label": None}
        self.assertEqual(ids.claim_commitment(salt, self.CLAIM),
                         hashlib.sha256(b"witness-commit/1|claim|" + salt + jcs.canonical(self.CLAIM)).hexdigest())
        self.assertEqual(ids.body_commitment(salt, body),
                         hashlib.sha256(b"witness-commit/1|body|" + salt + jcs.canonical(body)).hexdigest())

    def test_changing_one_byte_changes_every_id(self):
        salt = bytes(16)
        other = dict(self.CLAIM, assertion=False)
        self.assertNotEqual(ids.claim_id(self.CLAIM), ids.claim_id(other))
        self.assertNotEqual(ids.claim_commitment(salt, self.CLAIM), ids.claim_commitment(salt, other))
        self.assertNotEqual(ids.claim_commitment(salt, self.CLAIM), ids.claim_commitment(b"\x01" + salt[1:], self.CLAIM))

    def test_base64url_salt_round_trip(self):
        salt = bytes(range(16))
        s = ids.b64url(salt)
        self.assertNotIn("=", s)
        self.assertEqual(ids.b64url_decode(s), salt)
        self.assertEqual(ids.b64url_decode(s + "=="), salt)


if __name__ == "__main__":
    unittest.main()
