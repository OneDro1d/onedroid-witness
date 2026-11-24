"""claim_fetcher: the claim witness's page fetcher (slice B2a).

A small HTTP service the witness calls to observe a web page. Chromium runs in an unprivileged user + network
namespace that has only a loopback interface; its one way out is a loopback listener bridged over a Unix socket to an
egress proxy outside the namespace, which enforces the address rules. See README_FETCHER.md.
"""
FETCHER_ID = "onedroid-fetcher"
VERSION = "1.0.0"
