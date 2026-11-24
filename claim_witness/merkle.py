"""The batch Merkle tree (SPEC §1, §7.2), exactly RFC 9162 §2.1 (the RFC 6962 hashing), over the signing-log leaves in log order:

    leaf  = H(0x00 || payload)                          (ids.leaf_hash; stored with each signing-log row)
    MTH({d0})   = the leaf itself
    MTH(D[n])   = H(0x01 || MTH(D[0:k]) || MTH(D[k:n]))  with k the largest power of two smaller than n (n > 1)

An inclusion path is PATH(m, D[n]) of RFC 9162 §2.1.3.1, written bottom up as lowercase hex; root_from_path is the check of
§2.1.3.2. An empty tree is never sealed. witness-verify restates root_from_path (verify.merkle_root_from_path)."""
import hashlib

from .ids import leaf_hash  # noqa: F401  (re-exported: the leaf rule lives in one place)


def _node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(leaves):
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return _node(_mth(leaves[:k]), _mth(leaves[k:]))


def _raw(leaves_hex):
    if not leaves_hex:
        raise ValueError("an empty tree has no root here: a batch holds at least one leaf")
    return [bytes.fromhex(x) for x in leaves_hex]


def root(leaves_hex):
    """The tree head of the leaves (hex in, hex out)."""
    return _mth(_raw(leaves_hex)).hex()


def _path(m, leaves):
    n = len(leaves)
    if n == 1:
        return []
    k = _split(n)
    if m < k:
        return _path(m, leaves[:k]) + [_mth(leaves[k:])]
    return _path(m - k, leaves[k:]) + [_mth(leaves[:k])]


def path(leaves_hex, index):
    """The inclusion path of leaf `index`, bottom up."""
    raw = _raw(leaves_hex)
    if not 0 <= index < len(raw):
        raise ValueError("index outside the tree")
    return [x.hex() for x in _path(index, raw)]


def paths(leaves_hex):
    """Every leaf's path, computed in one pass over the levels (a batch can hold 100,000 leaves)."""
    raw = _raw(leaves_hex)
    out = [[] for _ in raw]

    def walk(lo, hi):
        """The subtree hash of raw[lo:hi]; appends the sibling hashes to the paths of its leaves."""
        if hi - lo == 1:
            return raw[lo]
        k = _split(hi - lo)
        left, right = walk(lo, lo + k), walk(lo + k, hi)
        for i in range(lo, lo + k):
            out[i].append(right)
        for i in range(lo + k, hi):
            out[i].append(left)
        return _node(left, right)

    walk(0, len(raw))
    return [[x.hex() for x in p] for p in out]


def root_from_path(leaf_hex, index, size, path_hex):
    """RFC 9162 §2.1.3.2: the root the leaf and its path give, or None when they cannot fit a tree of that size."""
    try:
        r = bytes.fromhex(leaf_hex)
        hashes = [bytes.fromhex(p) for p in path_hex]
    except (TypeError, ValueError):
        return None
    if not (isinstance(index, int) and isinstance(size, int)) or not 0 <= index < size or len(r) != 32:
        return None
    fn, sn = index, size - 1
    for p in hashes:
        if len(p) != 32 or sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = _node(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    return r.hex() if sn == 0 else None
