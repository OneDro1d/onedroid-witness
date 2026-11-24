"""capture: post (slice B5a, SPEC §2.2, §2.3): Bluesky post URLs, the AT Protocol proof (CAR, DAG-CBOR, MST path, the
commit signature against the DID document's key), handle resolution both ways, platform.json, and the API.

Unit tests use the recorded fixtures in fixtures/bsky (a real public post's CAR, its DID documents and DNS answers,
fetched 24 Nov 2026) and synthetic repositories signed by tests_fetcher/atp_helpers.py. Nothing here uses the network:
the platform part takes a getter and a TXT lookup, and the getter test runs through the real EgressProxy with the seam
connector of conftest.py."""
import asyncio
import hashlib
import http.client
import json
import socket
import struct
import threading
import urllib.parse

import pytest

from claim_fetcher import atproto, capture as capture_mod, dnsclient, post, server
from claim_fetcher.proxy import EgressProxy

from atp_helpers import (OTHER_DID, OTHER_PDS, PDS, REAL_DID, REAL_RECORD_CID, REAL_RKEY, REAL_URL, did_doc, dns_txt,
                          make_repo, multikey, other_doc, post_record, real_car, real_doc, real_key)
from conftest import FIXTURE_IP, FakeResolver, seam_connector

COLL = "app.bsky.feed.post"
SPEC_FIELDS = {"name", "post_uri", "author_did", "handle", "handle_resolution", "did_doc_sha256", "signature",
               "commit_cid", "created_at_claimed"}


# URLs ---------------------------------------------------------------------------------------------------------------

def test_parse_post_url_handle_and_did():
    assert atproto.parse_post_url(REAL_URL) == ("bsky.app", REAL_RKEY)
    assert atproto.parse_post_url(f"https://bsky.app/profile/{REAL_DID}/post/{REAL_RKEY}") == (REAL_DID, REAL_RKEY)
    assert atproto.parse_post_url("https://bsky.app/profile/Jay.Bsky.Team/post/3abc") == ("jay.bsky.team", "3abc")


@pytest.mark.parametrize("url", [
    "https://x.com/someone/status/1",
    "https://www.linkedin.com/posts/someone_activity-1",
    "https://www.tiktok.com/@someone/video/1",
    "http://bsky.app/profile/bsky.app/post/3n2opitxdyc2j",
    "https://bsky.app/profile/bsky.app",
    "https://bsky.app/profile/bsky.app/post/",
    "https://bsky.app/profile/bsky.app/post/bad%20key",
    "https://bsky.app/profile/not_a_handle/post/3abc",
    "https://evil.example/profile/bsky.app/post/3abc",
    "https://bsky.app/profile/bsky.app/post/3abc?x=1",
])
def test_parse_post_url_refuses_everything_else(url):
    with pytest.raises(ValueError):
        atproto.parse_post_url(url)


def test_handle_syntax():
    assert atproto.normalize_handle("Bsky.App") == "bsky.app"
    for bad in ("", "bsky", "-a.com", "a..com", "a.com.", "x" * 254 + ".com", "under_score.com", "a.123"):
        with pytest.raises(ValueError):
            atproto.normalize_handle(bad)


# DAG-CBOR, CIDs, CAR --------------------------------------------------------------------------------------------------

def test_cbor_round_trip_and_canonical_key_order():
    obj = {"bb": 1, "a": [1, -2, 300000, b"\x00\x01", "x", None, True], "ccc": {"z": 0}}
    data = atproto.cbor_encode(obj)
    assert atproto.cbor_decode(data) == obj
    # DAG-CBOR orders map keys by length, then bytes
    assert data.index(b"a") < data.index(b"bb") < data.index(b"ccc")


def test_cbor_refuses_floats_trailing_bytes_and_indefinite_lengths():
    with pytest.raises(atproto.ProofError):
        atproto.cbor_decode(b"\xfb" + struct.pack(">d", 1.5))
    with pytest.raises(atproto.ProofError):
        atproto.cbor_decode(atproto.cbor_encode(1) + b"\x00")
    with pytest.raises(atproto.ProofError):
        atproto.cbor_decode(b"\x9f\x01\xff")


def test_real_car_blocks_hash_to_their_cids():
    roots, blocks = atproto.read_car(real_car())
    assert len(roots) == 1 and roots[0] in blocks
    for cid, data in blocks.items():
        assert atproto.cid_for(data) == cid
    assert str(atproto.CID.parse_str(REAL_RECORD_CID)) == REAL_RECORD_CID
    assert atproto.CID.parse_str(REAL_RECORD_CID) in blocks


def test_car_with_a_changed_block_is_refused():
    car = bytearray(real_car())
    car[-5] ^= 0x01  # inside the last block's data
    with pytest.raises(atproto.ProofError):
        atproto.read_car(bytes(car))


# keys and signatures --------------------------------------------------------------------------------------------------

def test_real_multikey_is_a_compressed_secp256k1_key():
    curve, point = atproto.parse_multikey(real_key())
    assert curve == "secp256k1"
    assert atproto.encode_multikey(curve, point) == real_key()


@pytest.mark.parametrize("curve", ["secp256k1", "p256"])
def test_ecdsa_verify_low_s_only(curve):
    priv = 0xC0FFEE1234
    mk = multikey(curve, priv)
    c, pub = atproto.parse_multikey(mk)
    h = hashlib.sha256(b"message").digest()
    from atp_helpers import sign
    assert atproto.ecdsa_verify(c, pub, h, sign(curve, priv, h))
    assert not atproto.ecdsa_verify(c, pub, h, sign(curve, priv, h, high_s=True))  # AT Protocol: low-S only
    assert not atproto.ecdsa_verify(c, pub, hashlib.sha256(b"other").digest(), sign(curve, priv, h))
    assert not atproto.ecdsa_verify(c, pub, h, b"\x00" * 64)


def test_multikey_refuses_unknown_codecs_and_bad_points():
    with pytest.raises(ValueError):
        atproto.parse_multikey("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")  # ed25519 is not an atproto key
    with pytest.raises(ValueError):
        atproto.parse_multikey("mAAAA")  # not base58btc
    with pytest.raises(ValueError):
        atproto.parse_multikey("z" + atproto.b58encode(b"\xe7\x01\x02" + b"\x00" * 32))  # not on the curve


# the proof ----------------------------------------------------------------------------------------------------------

def test_real_post_verifies():
    got = atproto.verify_record(real_car(), REAL_DID, COLL, REAL_RKEY, real_key())
    assert got["signature"] == "verified", got
    assert got["record_cid"] == REAL_RECORD_CID
    assert got["commit_cid"].startswith("bafyrei")
    assert got["record"]["$type"] == COLL
    assert got["record"]["createdAt"] == "2026-11-19T18:33:36.813Z"
    assert got["record"]["text"].startswith("v1.138 is live!")


def test_real_post_with_a_tampered_signature_fails():
    roots, blocks = atproto.read_car(real_car())
    commit = atproto.cbor_decode(blocks[roots[0]])
    commit["sig"] = bytes([commit["sig"][0] ^ 0x01]) + commit["sig"][1:]
    data = atproto.cbor_encode(commit)
    cid = atproto.cid_for(data)
    rest = [(c, d) for c, d in blocks.items() if c != roots[0]]
    car = atproto.build_car([cid], [(cid, data)] + rest)
    got = atproto.verify_record(car, REAL_DID, COLL, REAL_RKEY, real_key())
    assert got["signature"] == "failed"
    assert got["reason"] == "bad-signature"


def test_real_post_under_another_did_or_key_fails():
    got = atproto.verify_record(real_car(), OTHER_DID, COLL, REAL_RKEY, real_key())
    assert (got["signature"], got["reason"]) == ("failed", "commit-did-mismatch")
    other_key = json.loads(other_doc())["verificationMethod"][0]["publicKeyMultibase"]
    got = atproto.verify_record(real_car(), REAL_DID, COLL, REAL_RKEY, other_key)
    assert (got["signature"], got["reason"]) == ("failed", "bad-signature")


def test_real_car_does_not_prove_another_rkey():
    got = atproto.verify_record(real_car(), REAL_DID, COLL, "3n2opitxdyc2k", real_key())
    assert got["signature"] == "failed" and got["reason"] in ("record-not-in-proof", "proof-incomplete")


@pytest.mark.parametrize("curve", ["secp256k1", "p256"])
def test_synthetic_repo_verifies_for_both_curves(curve):
    did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
    car, commit_cid, recs = make_repo(did, {f"{COLL}/3aaa": post_record("one"), f"{COLL}/3bbb": post_record("two")},
                                      curve_name=curve, priv=0xABCDEF)
    got = atproto.verify_record(car, did, COLL, "3bbb", multikey(curve, 0xABCDEF))
    assert got["signature"] == "verified"
    assert got["record_cid"] == str(recs[f"{COLL}/3bbb"])
    assert got["record"]["text"] == "two"
    assert got["commit_cid"] == str(commit_cid)


def test_synthetic_negatives():
    did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
    recs = {f"{COLL}/3aaa": post_record()}
    key = multikey("secp256k1", 0xABCDEF)
    car, _, _ = make_repo(did, recs, priv=0xABCDEF, tamper_sig=True)
    assert atproto.verify_record(car, did, COLL, "3aaa", key)["signature"] == "failed"
    car, _, _ = make_repo(did, recs, priv=0xABCDEF, high_s=True)
    assert atproto.verify_record(car, did, COLL, "3aaa", key)["signature"] == "failed"
    car, _, _ = make_repo(did, recs, priv=0xABCDEF, commit_did="did:plc:bbbbbbbbbbbbbbbbbbbbbbbb")
    assert atproto.verify_record(car, did, COLL, "3aaa", key)["reason"] == "commit-did-mismatch"
    car, _, _ = make_repo(did, recs, priv=0x999)  # signed by another key
    assert atproto.verify_record(car, did, COLL, "3aaa", key)["reason"] == "bad-signature"
    assert atproto.verify_record(b"not a car", did, COLL, "3aaa", key)["signature"] == "failed"


def test_did_document_reading():
    info = atproto.did_doc_info(real_doc(), REAL_DID)
    assert info["key"] == real_key()
    assert info["pds"] == PDS
    assert info["handles"] == ["bsky.app"]
    with pytest.raises(ValueError):
        atproto.did_doc_info(real_doc(), OTHER_DID)  # the document of another DID
    no_key = json.dumps({"id": REAL_DID, "alsoKnownAs": [], "verificationMethod": [], "service": []}).encode()
    assert atproto.did_doc_info(no_key, REAL_DID)["key"] is None
    assert atproto.did_doc_url("did:plc:z72i7hdynmk6r22z27h6tvur") == "https://plc.directory/did:plc:z72i7hdynmk6r22z27h6tvur"
    assert atproto.did_doc_url("did:web:example.com") == "https://example.com/.well-known/did.json"
    for bad in ("did:key:z6Mk", "did:plc:short", "did:web:localhost", "did:web:a.com:path"):
        with pytest.raises(ValueError):
            atproto.did_doc_url(bad)


# the platform part with recorded answers -------------------------------------------------------------------------------

class Net:
    """A getter and a TXT lookup over recorded answers; records every request."""

    def __init__(self, routes=None, txt=None):
        self.routes = dict(routes or {})
        self.txt_answers = dict(txt if txt is not None else dns_txt())
        self.calls, self.txt_calls = [], []

    async def get(self, url, accept, max_bytes):
        self.calls.append(url)
        got = self.routes.get(url)
        if got is None:
            return 404, "text/plain", b"not found"
        if isinstance(got, BaseException):
            raise got
        return got

    async def txt(self, name):
        self.txt_calls.append(name)
        return list(self.txt_answers.get(name, []))


def real_routes():
    return {
        f"https://plc.directory/{REAL_DID}": (200, "application/did+ld+json", real_doc()),
        f"https://plc.directory/{OTHER_DID}": (200, "application/did+ld+json", other_doc()),
        f"{PDS}/xrpc/com.atproto.sync.getRecord?did={urllib.parse.quote(REAL_DID)}&collection={COLL}&rkey={REAL_RKEY}":
            (200, "application/vnd.ipld.car", real_car()),
    }


def run(coro):
    return asyncio.run(coro)


def test_platform_for_the_real_handle():
    net = Net(real_routes())
    pj, files = run(post.platform_capture(REAL_URL, "bsky.app", net.get, net.txt))
    fields = post.platform_fields(pj)
    assert set(fields) == SPEC_FIELDS
    assert fields["name"] == "bluesky"
    assert fields["post_uri"] == f"at://{REAL_DID}/{COLL}/{REAL_RKEY}"
    assert fields["author_did"] == REAL_DID
    assert fields["handle"] == "bsky.app"
    hr = fields["handle_resolution"]
    assert set(hr) == {"method", "result_did", "at", "bidirectional"}
    assert (hr["method"], hr["result_did"], hr["bidirectional"]) == ("dns-txt", REAL_DID, True)
    assert fields["did_doc_sha256"] == hashlib.sha256(real_doc()).hexdigest()
    assert fields["signature"] == "verified"
    assert fields["created_at_claimed"] == "2026-11-19T18:33:36.813Z"
    assert files["post.car"] == real_car() and files["did-document.json"] == real_doc()
    assert net.txt_calls == ["_atproto.bsky.app"]
    assert all(urllib.parse.urlsplit(u).hostname in ("plc.directory", "puffball.us-east.host.bsky.network")
               for u in net.calls)


def test_platform_for_another_real_handle_resolves_it_both_ways():
    net = Net(real_routes())
    pj, files = run(post.platform_capture(REAL_URL, "atproto.com", net.get, net.txt))
    f = post.platform_fields(pj)
    assert f["author_did"] == REAL_DID and f["signature"] == "verified"
    assert f["handle"] == "atproto.com"
    assert (f["handle_resolution"]["result_did"], f["handle_resolution"]["bidirectional"]) == (OTHER_DID, True)
    assert pj["handle_did_doc_sha256"] == hashlib.sha256(other_doc()).hexdigest()
    assert files["handle-did-document.json"] == other_doc()


def test_one_way_handle_is_not_bidirectional():
    # DNS says the handle belongs to the author's DID, but the author's document does not list it
    net = Net(real_routes(), txt=dict(dns_txt(), **{"_atproto.impostor.example.com": [f"did={REAL_DID}"]}))
    pj, _ = run(post.platform_capture(REAL_URL, "impostor.example.com", net.get, net.txt))
    hr = post.platform_fields(pj)["handle_resolution"]
    assert (hr["method"], hr["result_did"], hr["bidirectional"]) == ("dns-txt", REAL_DID, False)


def test_handle_falls_back_to_https_well_known():
    routes = dict(real_routes(), **{"https://someone.example.org/.well-known/atproto-did": (200, "text/plain",
                                                                                            OTHER_DID.encode() + b"\n")})
    net = Net(routes)
    pj, _ = run(post.platform_capture(REAL_URL, "someone.example.org", net.get, net.txt))
    hr = post.platform_fields(pj)["handle_resolution"]
    assert (hr["method"], hr["result_did"], hr["bidirectional"]) == ("well-known", OTHER_DID, False)
    assert "_atproto.someone.example.org" in net.txt_calls


def test_unresolvable_handle():
    net = Net(real_routes())
    pj, _ = run(post.platform_capture(REAL_URL, "nobody.example.net", net.get, net.txt))
    hr = post.platform_fields(pj)["handle_resolution"]
    assert (hr["method"], hr["result_did"], hr["bidirectional"]) == ("well-known", None, False)
    assert post.platform_fields(pj)["signature"] == "verified"  # the post itself is still proven


def test_two_did_txt_records_resolve_nothing():
    net = Net(real_routes(), txt=dict(dns_txt(), **{"_atproto.two.example.com": [f"did={REAL_DID}", f"did={OTHER_DID}"]}))
    pj, _ = run(post.platform_capture(REAL_URL, "two.example.com", net.get, net.txt))
    assert post.platform_fields(pj)["handle_resolution"]["result_did"] is None


def test_url_by_did_needs_no_handle_lookup_for_the_repo():
    net = Net(real_routes())
    pj, _ = run(post.platform_capture(f"https://bsky.app/profile/{REAL_DID}/post/{REAL_RKEY}", "bsky.app", net.get, net.txt))
    f = post.platform_fields(pj)
    assert f["signature"] == "verified" and f["handle_resolution"]["bidirectional"] is True


def test_default_handle_is_the_urls_handle():
    net = Net(real_routes())
    pj, _ = run(post.platform_capture(REAL_URL, None, net.get, net.txt))
    assert post.platform_fields(pj)["handle"] == "bsky.app"


def test_record_not_found_is_not_available():
    routes = real_routes()
    key = [k for k in routes if "getRecord" in k][0]
    routes[key] = (400, "application/json", b'{"error":"RecordNotFound"}')
    pj, files = run(post.platform_capture(REAL_URL, "bsky.app", Net(routes).get, Net().txt))
    f = post.platform_fields(pj)
    assert f["signature"] == "not-available" and f["commit_cid"] is None and f["created_at_claimed"] is None
    assert "post.car" not in files


def test_did_document_without_a_key_is_not_available():
    doc = json.dumps({"id": REAL_DID, "alsoKnownAs": ["at://bsky.app"], "verificationMethod": [],
                      "service": [{"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": PDS}]}).encode()
    routes = dict(real_routes(), **{f"https://plc.directory/{REAL_DID}": (200, "application/json", doc)})
    pj, _ = run(post.platform_capture(REAL_URL, "bsky.app", Net(routes).get, Net().txt))
    assert post.platform_fields(pj)["signature"] == "not-available"


def test_a_tampered_car_from_the_pds_is_failed():
    routes = real_routes()
    key = [k for k in routes if "getRecord" in k][0]
    car = bytearray(real_car())
    car[-5] ^= 1
    routes[key] = (200, "application/vnd.ipld.car", bytes(car))
    pj, _ = run(post.platform_capture(REAL_URL, "bsky.app", Net(routes).get, Net().txt))
    assert post.platform_fields(pj)["signature"] == "failed"


def test_network_failure_on_the_did_document_is_a_capture_error():
    routes = dict(real_routes(), **{f"https://plc.directory/{REAL_DID}": post.FetchError("timeout", "plc.directory")})
    with pytest.raises(post.FetchError) as e:
        run(post.platform_capture(REAL_URL, "bsky.app", Net(routes).get, Net().txt))
    assert e.value.code == "timeout"


def test_unknown_did_document_status_is_unreachable():
    routes = dict(real_routes(), **{f"https://plc.directory/{REAL_DID}": (404, "text/plain", b"DID not registered")})
    with pytest.raises(post.FetchError) as e:
        run(post.platform_capture(REAL_URL, "bsky.app", Net(routes).get, Net().txt))
    assert e.value.code == "unreachable"


def test_pds_on_a_private_address_is_never_asked_directly():
    # the PDS named by a DID document is fetched like any target: the getter (the proxy) judges its address
    doc = did_doc(REAL_DID, real_key(), ["bsky.app"], pds="https://10.0.0.1")
    routes = dict(real_routes(), **{f"https://plc.directory/{REAL_DID}": (200, "application/json", doc)})
    net = Net(routes)
    pj, _ = run(post.platform_capture(REAL_URL, "bsky.app", net.get, net.txt))
    assert post.platform_fields(pj)["signature"] == "not-available"  # a PDS that is not an https name is not asked
    assert not any("10.0.0.1" in u for u in net.calls)


def test_created_at_that_is_not_a_time_is_dropped():
    did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
    car, _, _ = make_repo(did, {f"{COLL}/3aaa": post_record(created="soon, I promise")}, priv=0xABCDEF)
    key = multikey("secp256k1", 0xABCDEF)
    routes = {f"https://plc.directory/{did}": (200, "application/json",
                                                did_doc(did, key, ["a.example.com"], pds="https://pds.example.com")),
              f"https://pds.example.com/xrpc/com.atproto.sync.getRecord?did={urllib.parse.quote(did)}&collection={COLL}&rkey=3aaa":
                  (200, "application/vnd.ipld.car", car)}
    net = Net(routes, txt={"_atproto.a.example.com": [f"did={did}"]})
    pj, _ = run(post.platform_capture(f"https://bsky.app/profile/{did}/post/3aaa", "a.example.com", net.get, net.txt))
    f = post.platform_fields(pj)
    assert f["signature"] == "verified" and f["handle_resolution"]["bidirectional"] is True
    assert f["created_at_claimed"] is None


# DNS TXT --------------------------------------------------------------------------------------------------------------

def _txt_reply(packet, strings, rcode=0, owner=None):
    qid = packet[:2]
    q = packet[12:]
    header = qid + struct.pack("!HHHHH", 0x8180 | rcode, 1, len(strings), 0, 0)
    out = header + q
    for s in strings:
        raw = s.encode()
        rdata = bytes([len(raw)]) + raw
        name = b"\xc0\x0c" if owner is None else owner
        out += name + struct.pack("!HHIH", 16, 1, 60, len(rdata)) + rdata
    return out


def test_txt_lookup_through_the_public_resolver():
    sent = []

    def udp(server_, packet, timeout):
        sent.append(server_)
        return _txt_reply(packet, ["did=did:plc:z72i7hdynmk6r22z27h6tvur", "other=1"])

    r = dnsclient.PublicResolver(["1.1.1.1"], udp=udp)
    assert r.txt("_atproto.bsky.app") == ["did=did:plc:z72i7hdynmk6r22z27h6tvur", "other=1"]
    assert sent == ["1.1.1.1"]


def test_txt_nxdomain_is_empty_and_a_mismatched_reply_is_refused():
    r = dnsclient.PublicResolver(["1.1.1.1"], udp=lambda s, p, t: _txt_reply(p, [], rcode=3))
    assert r.txt("_atproto.nobody.example") == []
    bad = dnsclient.PublicResolver(["1.1.1.1", "8.8.8.8"],
                                   udp=lambda s, p, t: b"\x00\x00" + _txt_reply(p, ["did=x"])[2:])
    with pytest.raises(OSError):
        bad.txt("_atproto.bsky.app")


def test_txt_ignores_records_of_other_names():
    other_owner = b"\x04evil\x07example\x00"
    r = dnsclient.PublicResolver(["1.1.1.1"], udp=lambda s, p, t: _txt_reply(p, ["did=did:plc:x"], owner=other_owner))
    assert r.txt("_atproto.bsky.app") == []


# the getter through the real egress proxy ------------------------------------------------------------------------------

def test_proxy_getter_goes_through_the_egress_proxy(site_factory, tmp_path):
    site = site_factory({"/did.json": (200, {"Content-Type": "application/json"}, b'{"id": "x"}')})

    async def go():
        resolver = FakeResolver({"did.example.com": [FIXTURE_IP], "private.example.com": ["10.1.2.3"]})
        connector = seam_connector({(FIXTURE_IP, 80): (site.host, site.port)})
        proxy = EgressProxy(str(tmp_path / "egress.sock"), resolver=resolver, connector=connector)
        await proxy.start()
        try:
            get = post.ProxyGetter(proxy.socket_path, "OneDroidWitness/1.0")
            ok = await get("http://did.example.com/did.json", "application/json", 1 << 20)
            with pytest.raises(post.FetchError) as refused:
                await get("http://private.example.com/did.json", "application/json", 1 << 20)
            return ok, refused.value.code, connector.calls, [e.get("host") for e in proxy.log]
        finally:
            await proxy.close()

    ok, code, calls, hosts = asyncio.run(go())
    assert ok[0] == 200 and ok[2] == b'{"id": "x"}'
    assert code == "blocked"
    assert calls == [(FIXTURE_IP, 80)]  # the refused host was never dialled
    assert "did.example.com" in hosts and "private.example.com" in hosts


def test_proxy_getter_caps_the_body(site_factory, tmp_path):
    site = site_factory({"/big": (200, {"Content-Type": "application/octet-stream"}, b"x" * 5000)})

    async def go():
        resolver = FakeResolver({"big.example.com": [FIXTURE_IP]})
        connector = seam_connector({(FIXTURE_IP, 80): (site.host, site.port)})
        proxy = EgressProxy(str(tmp_path / "egress.sock"), resolver=resolver, connector=connector)
        await proxy.start()
        try:
            with pytest.raises(post.FetchError) as e:
                await post.ProxyGetter(proxy.socket_path, "ua")("http://big.example.com/big", "*/*", 1000)
            return e.value.code
        finally:
            await proxy.close()

    assert asyncio.run(go()) == "too-large"


# the capture and the API ----------------------------------------------------------------------------------------------

def test_capture_post_joins_the_page_capture_and_platform_json(monkeypatch):
    async def fake_page(url, viewport=(1280, 900), settings=None, resolver=None, connector=None):
        files = {"capture.wacz": b"w", "response.body": b"<html>post</html>", "screenshot.png": b"p",
                 "rendered.html": b"<html>post</html>", "hidden-nodes.json": b"[]"}
        m = capture_mod.build_manifest(url, url, [], "2026-11-24T10:00:00Z", 10, 200, [FIXTURE_IP], None, "allowed",
                                       "chromium", viewport, files)
        return capture_mod.Result(m, files, [])

    net = Net(real_routes())

    async def fake_platform(url, handle, settings, resolver, connector):
        return await post.platform_capture(url, handle, net.get, net.txt)

    monkeypatch.setattr(capture_mod, "capture", fake_page)
    monkeypatch.setattr(post, "run_platform", fake_platform)
    r = asyncio.run(post.capture_post(REAL_URL, "bsky.app"))
    names = [f["name"] for f in r.manifest["files"]]
    assert names[:5] == list(capture_mod.FILE_ORDER)
    assert {"platform.json", "post.car", "did-document.json"} <= set(names)
    pj = json.loads(r.files["platform.json"])
    assert r.manifest["platform"] == post.platform_fields(pj)
    assert set(r.manifest["platform"]) == SPEC_FIELDS
    for f in r.manifest["files"]:
        assert hashlib.sha256(r.files[f["name"]]).hexdigest() == f["sha256"]
    tar = capture_mod.to_tar(r.manifest, r.files)
    assert b"platform.json" in tar


def test_capture_post_refuses_a_url_that_is_not_a_bluesky_post_before_any_request(monkeypatch):
    called = []
    monkeypatch.setattr(capture_mod, "capture", lambda *a, **k: called.append(a))
    monkeypatch.setattr(post, "run_platform", lambda *a, **k: called.append(a))
    with pytest.raises(capture_mod.CaptureError) as e:
        asyncio.run(post.capture_post("https://x.com/someone/status/1", None))
    assert e.value.code == "bad-request" and not called


def test_capture_post_maps_a_platform_fetch_failure_to_its_code(monkeypatch):
    async def fake_page(url, viewport=(1280, 900), settings=None, resolver=None, connector=None):
        files = {n: b"x" for n in capture_mod.FILE_ORDER}
        return capture_mod.Result(capture_mod.build_manifest(url, url, [], "2026-11-24T10:00:00Z", 1, 200, [], None,
                                                             "allowed", "c", viewport, files), files, [])

    async def failing(url, handle, settings, resolver, connector):
        raise post.FetchError("blocked", "address-not-public 10.0.0.1")

    monkeypatch.setattr(capture_mod, "capture", fake_page)
    monkeypatch.setattr(post, "run_platform", failing)
    with pytest.raises(capture_mod.CaptureError) as e:
        asyncio.run(post.capture_post(REAL_URL, "bsky.app"))
    assert e.value.code == "blocked" and e.value.http_status == 403


def _api(capture_fn):
    srv = server.make_server("127.0.0.1", 0, b"s3cret", capture_fn, {"passed": True})
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _post_json(srv, body):
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
    conn.request("POST", "/v1/capture", json.dumps(body), {"X-Fetcher-Secret": "s3cret",
                                                           "Content-Type": "application/json"})
    resp = conn.getresponse()
    return resp.status, resp.read()


def test_api_accepts_capture_post_with_a_handle():
    seen = []

    def capture_fn(url, viewport, kind="page", handle=None):
        seen.append((url, kind, handle))
        files = {"platform.json": b"{}"}
        return {"files": [{"name": "platform.json", "sha256": hashlib.sha256(b"{}").hexdigest(), "size": 2}]}, files

    srv = _api(capture_fn)
    try:
        status, _ = _post_json(srv, {"url": REAL_URL, "capture": "post", "handle": "Bsky.App"})
        assert status == 200
        assert seen == [(REAL_URL, "post", "bsky.app")]
        for body in ({"url": REAL_URL, "capture": "post", "handle": "not a handle"},
                     {"url": "https://x.com/a/status/1", "capture": "post"},
                     {"url": REAL_URL, "capture": "page", "handle": "bsky.app"},
                     {"url": REAL_URL, "capture": "video"}):
            status, data = _post_json(srv, body)
            assert status == 400 and json.loads(data)["error"] == "bad-request", body
        assert len(seen) == 1
    finally:
        srv.shutdown()
        srv.server_close()


def test_api_page_capture_is_unchanged():
    seen = []

    def capture_fn(url, viewport, kind="page", handle=None):
        seen.append((url, kind, handle))
        return {"files": []}, {}

    srv = _api(capture_fn)
    try:
        assert _post_json(srv, {"url": "https://example.com/", "capture": "page"})[0] == 200
        assert _post_json(srv, {"url": "https://example.com/"})[0] == 200
        assert seen == [("https://example.com/", "page", None)] * 2
    finally:
        srv.shutdown()
        srv.server_close()


def test_no_socket_is_opened_for_a_refused_post_url(monkeypatch):
    opened = []
    real = socket.socket

    def spy(*a, **k):
        opened.append(a)
        return real(*a, **k)

    monkeypatch.setattr(socket, "socket", spy)
    with pytest.raises(capture_mod.CaptureError):
        asyncio.run(post.capture_post("https://www.linkedin.com/posts/someone_activity-1", None))
    assert opened == []
