"""Address, host, URL and redirect rules (claim_fetcher.addr): the table every egress decision is made from."""
import pytest

from claim_fetcher import addr
from conftest import FakeResolver

REFUSED_IPS = [
    # IPv4: this network, private, CGNAT, loopback, link-local (metadata), Azure wire server, IETF/TEST-NETs,
    # benchmarking, multicast, reserved, broadcast
    "0.0.0.0", "0.1.2.3", "10.0.0.1", "10.255.255.255", "100.64.0.1", "100.127.255.254", "127.0.0.1", "127.1.2.3",
    "169.254.169.254", "169.254.0.1", "168.63.129.16", "172.16.0.1", "172.31.255.255", "192.168.1.1", "192.0.0.1",
    "192.0.2.1", "198.18.0.1", "198.19.255.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "239.255.255.250",
    "240.0.0.1", "255.255.255.255",
    # IPv6: unspecified, loopback, link-local, unique-local, multicast, site-local, documentation, discard
    "::", "::1", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "fec0::1", "2001:db8::1", "100::1",
    # IPv6 forms that carry an IPv4 address of a refused range
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::ffff:100.64.0.1", "::127.0.0.1",
    "64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::a00:1", "2002:7f00:1::", "2002:a00:1::",
    # Teredo and NAT64 are refused whatever they embed: their gateways are infrastructure
    "2001:0:4136:e378:8000:63bf:3fff:fdd2", "64:ff9b::5db8:d70e",
    # not an address at all
    "not-an-ip", "", "1.2.3", "1.2.3.4.5",
]

ALLOWED_IPS = ["93.184.215.14", "1.1.1.1", "8.8.8.8", "76.76.21.21", "2606:4700:4700::1111",
               "2a00:1450:4001:82a::200e", "::ffff:93.184.215.14"]


@pytest.mark.parametrize("ip", REFUSED_IPS)
def test_refused_addresses(ip):
    assert addr.ip_allowed(ip) is False


@pytest.mark.parametrize("ip", ALLOWED_IPS)
def test_public_addresses_allowed(ip):
    assert addr.ip_allowed(ip) is True


def test_cluster_cidrs_refused_in_every_form():
    extra = addr.parse_cidrs("52.0.0.0/8, fd00:10::/64 20.30.0.0/16")
    assert addr.ip_allowed("52.1.2.3", extra) is False
    assert addr.ip_allowed("::ffff:52.1.2.3", extra) is False
    assert addr.ip_allowed("20.30.4.5", extra) is False
    assert addr.ip_allowed("fd00:10::5", extra) is False
    assert addr.ip_allowed("53.1.2.3", extra) is True


def test_parse_cidrs_empty_and_placeholder():
    assert addr.parse_cidrs("") == ()
    assert addr.parse_cidrs(None) == ()
    with pytest.raises(ValueError):
        addr.parse_cidrs("CLUSTER_CIDRS_PLACEHOLDER")
    with pytest.raises(ValueError):
        addr.parse_cidrs("10.0.0.0/33")


# hosts --------------------------------------------------------------------------------------------------------------

RESOLVER = {
    "127.0.0.1.nip.io": ["127.0.0.1"],
    "10.0.0.1.sslip.io": ["10.0.0.1"],
    "169.254.169.254.nip.io": ["169.254.169.254"],
    "mixed.test": ["93.184.215.14", "10.0.0.1"],
    "v6local.test": ["::1"],
    "mapped.test": ["::ffff:169.254.169.254"],
    "nat64.test": ["64:ff9b::a00:1"],
    "cgnat.test": ["100.64.1.1"],
    "ok.test": ["93.184.215.14"],
    "ok6.test": ["2606:4700:4700::1111", "1.1.1.1"],
    "empty.test": [],
}


@pytest.mark.parametrize("host", ["127.0.0.1.nip.io", "10.0.0.1.sslip.io", "169.254.169.254.nip.io", "mixed.test",
                                  "v6local.test", "mapped.test", "nat64.test", "cgnat.test"])
def test_names_resolving_to_refused_addresses_are_blocked(host):
    with pytest.raises(addr.Refused) as e:
        addr.vet_host(host, 443, resolver=FakeResolver(RESOLVER))
    assert e.value.code == "blocked"


def test_public_name_returns_vetted_addresses_in_resolver_order():
    r = FakeResolver(RESOLVER)
    assert addr.vet_host("ok6.test", 443, resolver=r) == ["2606:4700:4700::1111", "1.1.1.1"]
    assert r.calls == ["ok6.test"]  # resolved exactly once


@pytest.mark.parametrize("host", ["nx.test", "empty.test"])
def test_unresolvable_is_unreachable(host):
    with pytest.raises(addr.Refused) as e:
        addr.vet_host(host, 443, resolver=FakeResolver(RESOLVER))
    assert e.value.code == "unreachable"


@pytest.mark.parametrize("host", ["localhost", "foo.localhost", "db.internal", "printer.local", "kubernetes.default.svc",
                                  "claim-witness.witness-dev.svc.cluster.local", "intranet", "router.home.arpa",
                                  "box.localdomain", "metadata.google.internal"])
def test_internal_names_blocked_without_resolving(host):
    r = FakeResolver({host: ["93.184.215.14"]})
    with pytest.raises(addr.Refused) as e:
        addr.vet_host(host, 443, resolver=r)
    assert e.value.code == "blocked"
    assert r.calls == []


@pytest.mark.parametrize("host", ["127.0.0.1", "2130706433", "0x7f000001", "017700000001", "127.1", "0x7f.0.0.1",
                                  "[::1]", "::1", "[::ffff:7f00:1]", "10.1", "169.254.169.254", "0"])
def test_numeric_hosts_judged_without_dns(host):
    r = FakeResolver({})
    with pytest.raises(addr.Refused) as e:
        addr.vet_host(host, 80, resolver=r)
    assert e.value.code == "blocked"
    assert r.calls == []


def test_numeric_public_host_allowed_without_dns():
    r = FakeResolver({})
    assert addr.vet_host("93.184.215.14", 443, resolver=r) == ["93.184.215.14"]
    assert r.calls == []


@pytest.mark.parametrize("port", [22, 8080, 0, 25, 6443, 10250])
def test_ports_other_than_80_and_443_refused(port):
    with pytest.raises(addr.Refused) as e:
        addr.vet_host("ok.test", port, resolver=FakeResolver(RESOLVER))
    assert e.value.code == "port"


def test_default_resolver_asks_for_the_absolute_name(monkeypatch):
    seen = []

    def fake_getaddrinfo(host, port, *a, **kw):
        seen.append(host)
        return [(2, 1, 6, "", ("93.184.215.14", port))]

    monkeypatch.setattr(addr.socket, "getaddrinfo", fake_getaddrinfo)
    assert addr.resolve("example.com") == ["93.184.215.14"]
    assert seen == ["example.com."]  # a trailing dot: the pod's DNS search list never expands the name


# URLs ---------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("url", ["ftp://ok.test/", "file:///etc/passwd", "javascript:alert(1)", "data:text/html,hi",
                                 "ws://ok.test/", "wss://ok.test/", "gopher://ok.test/", "", "ok.test/no-scheme",
                                 "chrome://settings", "view-source:https://ok.test/", "blob:https://ok.test/x"])
def test_schemes_other_than_http_https_refused(url):
    with pytest.raises(addr.Refused) as e:
        addr.check_url(url)
    assert e.value.code == "scheme"


@pytest.mark.parametrize("url", ["http://ok.test:8080/", "https://ok.test:22/", "http://ok.test:0/",
                                 "https://ok.test:65536/", "https://ok.test:x/"])
def test_url_ports_refused(url):
    with pytest.raises(addr.Refused) as e:
        addr.check_url(url)
    assert e.value.code == "port"


@pytest.mark.parametrize("url,expect", [
    ("https://ok.test/path?q=1#frag", ("https", "ok.test", 443)),
    ("http://ok.test/", ("http", "ok.test", 80)),
    ("HTTPS://OK.TEST/", ("https", "ok.test", 443)),
    ("http://ok.test:443/", ("http", "ok.test", 443)),
    ("https://ok.test:80/", ("https", "ok.test", 80)),
    ("https://bücher.test/", ("https", "xn--bcher-kva.test", 443)),
    ("https://[2606:4700:4700::1111]/", ("https", "2606:4700:4700::1111", 443)),
])
def test_valid_urls(url, expect):
    assert addr.check_url(url) == expect


@pytest.mark.parametrize("url", ["https://user:pw@ok.test/", "https://user@ok.test/", "https:///nohost", "http://"])
def test_credentials_or_no_host_refused(url):
    with pytest.raises(addr.Refused) as e:
        addr.check_url(url)
    assert e.value.code in ("blocked", "scheme")


def test_check_target_runs_url_then_host_rules():
    r = FakeResolver(RESOLVER)
    assert addr.check_target("https://ok.test/a", resolver=r) == ("https", "ok.test", 443, ["93.184.215.14"])
    with pytest.raises(addr.Refused) as e:
        addr.check_target("http://127.0.0.1.nip.io/", resolver=r)
    assert e.value.code == "blocked"


# redirects ----------------------------------------------------------------------------------------------------------

def test_redirect_relative_location_resolved_and_rechecked():
    assert addr.next_hop("https://ok.test/a/b", "../c?x=1", hops=1) == "https://ok.test/c?x=1"


@pytest.mark.parametrize("location,code", [("file:///etc/passwd", "scheme"), ("https://ok.test:8443/", "port"),
                                           ("gopher://ok.test/", "scheme")])
def test_redirect_to_bad_scheme_or_port_refused(location, code):
    with pytest.raises(addr.Refused) as e:
        addr.next_hop("https://ok.test/", location, hops=1)
    assert e.value.code == code


def test_redirect_to_private_host_refused_when_checked():
    url = addr.next_hop("https://ok.test/", "http://127.0.0.1.nip.io/admin", hops=1)
    with pytest.raises(addr.Refused) as e:
        addr.check_target(url, resolver=FakeResolver(RESOLVER))
    assert e.value.code == "blocked"


def test_too_many_redirects_refused():
    addr.next_hop("https://ok.test/", "/x", hops=5)
    with pytest.raises(addr.Refused) as e:
        addr.next_hop("https://ok.test/", "/x", hops=6)
    assert e.value.code == "blocked"
    assert "redirect" in e.value.detail
