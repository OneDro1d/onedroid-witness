"""B3 (d): the Merkle tree over signing-log leaves, RFC 9162 §2.1 (the RFC 6962 hashing): leaf = H(0x00 || payload),
node = H(0x01 || left || right), split at the largest power of two below n; inclusion paths per §2.1.3.1 and their check per
§2.1.3.2. The witness (claim_witness.merkle) and witness-verify (claim_witness.verify, standalone) must agree."""
import hashlib
import unittest

# RFC 6962's reference test data (certificate-transparency merkle tree tests): the eight leaf inputs and the root of the
# first n of them, for n = 1..8.
LEAVES = [b"", b"\x00", b"\x10", b"\x20\x21", b"\x30\x31", b"\x40\x41\x42\x43", b"\x50\x51\x52\x53\x54\x55\x56\x57",
          b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"]
ROOTS = ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
         "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
         "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
         "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
         "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
         "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
         "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
         "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"]


def leaf(b):
    return hashlib.sha256(b"\x00" + b).hexdigest()


class Tree(unittest.TestCase):
    def test_rfc6962_known_roots(self):
        from claim_witness import merkle
        for n in range(1, 9):
            self.assertEqual(merkle.root([leaf(x) for x in LEAVES[:n]]), ROOTS[n - 1], n)

    def test_leaf_hash_is_ids_leaf_hash(self):
        from claim_witness import ids, merkle
        self.assertEqual(merkle.leaf_hash(b"abc"), ids.leaf_hash(b"abc"))
        self.assertEqual(merkle.leaf_hash(b"abc"), leaf(b"abc"))

    def test_every_path_verifies_in_witness_and_verifier(self):
        from claim_witness import merkle, verify
        for n in range(1, 18):
            leaves = [leaf(b"payload-%d" % i) for i in range(n)]
            r = merkle.root(leaves)
            for i in range(n):
                p = merkle.path(leaves, i)
                self.assertTrue(all(isinstance(x, str) and len(x) == 64 for x in p))
                self.assertEqual(merkle.root_from_path(leaves[i], i, n, p), r, (n, i))
                self.assertEqual(verify.merkle_root_from_path(leaves[i], i, n, p), r, (n, i))

    def test_path_length_is_logarithmic(self):
        from claim_witness import merkle
        leaves = [leaf(b"%d" % i) for i in range(1024)]
        self.assertEqual(len(merkle.path(leaves, 517)), 10)

    def test_a_changed_path_hash_or_index_gives_another_root(self):
        from claim_witness import merkle, verify
        leaves = [leaf(b"x%d" % i) for i in range(7)]
        r, p = merkle.root(leaves), merkle.path(leaves, 3)
        bad = list(p)
        bad[0] = ("0" if bad[0][0] != "0" else "1") + bad[0][1:]
        self.assertNotEqual(verify.merkle_root_from_path(leaves[3], 3, 7, bad), r)
        self.assertNotEqual(verify.merkle_root_from_path(leaves[3], 2, 7, p), r)
        self.assertNotEqual(verify.merkle_root_from_path(leaves[4], 3, 7, p), r)

    def test_bad_inputs_give_none_in_the_verifier(self):
        from claim_witness import verify
        self.assertIsNone(verify.merkle_root_from_path(leaf(b"a"), 5, 3, []))
        self.assertIsNone(verify.merkle_root_from_path(leaf(b"a"), 0, 1, ["ab" * 32]))  # a path too long
        self.assertIsNone(verify.merkle_root_from_path("zz", 0, 1, []))

    def test_empty_tree_is_refused(self):
        from claim_witness import merkle
        with self.assertRaises(ValueError):
            merkle.root([])


if __name__ == "__main__":
    unittest.main()
