"""Grok CLI (``grok login``) billing path. Offline; no network."""
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from quota_providers import grok  # noqa: E402
from quota_providers.base import Deadline  # noqa: E402

PUBLIC = "https://auth.x.ai::id"
PAYLOAD = {"config": {
    "currentPeriod": {"type": "USAGE_PERIOD_TYPE_WEEKLY",
                      "start": "2026-10-05T06:11:07+00:00", "end": "2026-10-12T06:11:07+00:00"},
    "creditUsagePercent": 21.0, "onDemandCap": {"val": 0}, "onDemandUsed": {"val": 0},
    "productUsage": [{"product": "GrokBuild", "usagePercent": 21.0}],
    "prepaidBalance": {"val": 0}}}


def _write_auth(tmp, entries):
    with open(os.path.join(tmp, "auth.json"), "w") as fh:
        json.dump(entries, fh)


def _auth(tmp, expires, scope=PUBLIC, issuer="https://auth.x.ai", key="SYNTHETIC"):
    _write_auth(tmp, {scope: {"key": key, "expires_at": expires, "oidc_issuer": issuer}})


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _ok(payload=PAYLOAD):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return lambda req, timeout=None: _Resp(body)


class _Env(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        p = mock.patch.dict(os.environ, {"GROK_HOME": self.tmp})
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(self._tmp.cleanup)


class ParseTests(unittest.TestCase):
    def test_weekly_and_product_legend(self):
        res = grok._parse_cli_billing(PAYLOAD)
        w = res.windows[0]
        self.assertEqual((w.label, w.used_percent, w.reset_at),
                         ("Weekly Limit", 21.0, "2026-10-12T06:11:07+00:00"))
        self.assertEqual(res.details, ["Grok Build: 21% used"])  # zero cap/balance hidden

    def test_malformed_shapes_never_raise(self):
        for cfg in ({"productUsage": 5},
                    {"productUsage": [{"usagePercent": "21"}]},
                    {"creditUsagePercent": True},
                    {"creditUsagePercent": "21"}):
            with self.subTest(cfg=cfg):
                self.assertIsNone(grok._parse_cli_billing({"config": cfg}))
        res = grok._parse_cli_billing({"config": {"onDemandCap": {"val": 5}, "onDemandUsed": {"val": "x"}}})
        self.assertEqual(res.details, ["On-demand cap: 5"])
        res = grok._parse_cli_billing({"config": {"onDemandCap": {"val": 5}, "onDemandUsed": {"val": 0}}})
        self.assertEqual(res.details, ["On-demand: 0 / 5"])

    def test_huge_and_nonfinite_numbers_are_unknown(self):
        for raw in ('{"config":{"creditUsagePercent":%s}}' % ("9" * 400),
                    '{"config":{"creditUsagePercent":1e309}}'):
            with self.subTest(raw=raw[:40]):
                self.assertIsNone(grok._parse_cli_billing(json.loads(raw)))

    def test_absent_percent_is_not_reported_as_zero(self):
        cfg = {"currentPeriod": {"type": "USAGE_PERIOD_TYPE_WEEKLY", "end": "2026-10-12T06:11:07Z"}}
        self.assertIsNone(grok._parse_cli_billing({"config": cfg}))


class ExpiryTests(unittest.TestCase):
    def test_offsets_and_nanoseconds(self):
        cases = {
            "2026-10-10T04:48:32.903126404Z": datetime(2026, 10, 10, 4, 48, 32, 903126, timezone.utc),
            "2026-10-10T12:48:32.903126404+08:00": datetime(2026, 10, 10, 4, 48, 32, 903126, timezone.utc),
            "2026-10-09T23:48:32-05:00": datetime(2026, 10, 10, 4, 48, 32, tzinfo=timezone.utc),
            "2026-10-10T04:48:32": datetime(2026, 10, 10, 4, 48, 32, tzinfo=timezone.utc),
        }
        for raw, want in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(grok._parse_expiry(raw), want)

    def test_unparseable_is_none(self):
        for raw in (None, "", "soon", 123, "9999-12-31T23:59:59-05:00", "0001-01-01T00:00:00+05:00"):
            self.assertIsNone(grok._parse_expiry(raw))


class TokenTests(_Env):
    def test_enterprise_scope_is_never_selected(self):
        _write_auth(self.tmp, {
            "https://idp.example.com::corp": {"key": "ENTERPRISE", "expires_at": "2999-01-01T00:00:00Z",
                                              "oidc_issuer": "https://idp.example.com"},
            PUBLIC: {"key": "PUBLIC", "expires_at": "2999-01-01T00:00:00Z", "oidc_issuer": "https://auth.x.ai"},
        })
        self.assertEqual(grok._load_grok_cli_token(), ("PUBLIC", None))

    def test_only_enterprise_scope_means_no_credentials(self):
        _auth(self.tmp, "2999-01-01T00:00:00Z", scope="https://idp.example.com::c",
              issuer="https://idp.example.com")
        self.assertEqual(grok._load_grok_cli_token(), (None, "no-credentials"))

    def test_issuer_and_scope_must_agree(self):
        _write_auth(self.tmp, {
            PUBLIC: {"key": "LIAR", "expires_at": "2999-01-01T00:00:00Z", "oidc_issuer": "https://idp.example.com"},
            "https://idp.example.com::c": {"key": "LIAR2", "expires_at": "2999-01-01T00:00:00Z",
                                           "oidc_issuer": "https://auth.x.ai"},
        })
        self.assertEqual(grok._load_grok_cli_token(), (None, "no-credentials"))

    def test_missing_expiry_is_tried(self):
        _write_auth(self.tmp, {PUBLIC: {"key": "K", "oidc_issuer": "https://auth.x.ai"}})
        self.assertEqual(grok._load_grok_cli_token(), ("K", None))


class FetchTests(_Env):
    def test_cli_login_used_before_cookies(self):
        _auth(self.tmp, "2999-01-01T00:00:00.123456789Z")
        seen = {}

        def _open(req, timeout=None):
            seen["auth"] = req.get_header("Authorization")
            seen["timeout"] = timeout
            return _Resp(json.dumps(PAYLOAD).encode())

        with mock.patch.object(grok, "urlopen_no_redirect", _open), \
                mock.patch.object(grok, "_load_cookies", side_effect=AssertionError("cookies read")):
            res = grok.fetch_grok_quota()
        self.assertIsNone(res.unavailable_reason)
        self.assertEqual(seen["auth"], "Bearer SYNTHETIC")
        self.assertLessEqual(seen["timeout"], grok._FETCH_BUDGET_S)

    def test_expired_reports_reauth_and_spawns_nothing(self):
        _auth(self.tmp, "2000-01-01T00:00:00Z")
        with mock.patch.object(grok, "_load_cookies", return_value=None), \
                mock.patch("shutil.which", side_effect=AssertionError("spawned")):
            res = grok.fetch_grok_quota()
        self.assertEqual(res.unavailable_reason, "reauth-required")

    def test_no_cli_login_falls_through_to_cookie_reason(self):
        with mock.patch.object(grok, "_load_cookies", return_value=None):
            res = grok.fetch_grok_quota()
        self.assertEqual(res.unavailable_reason, "no-session-cookies")

    def test_http_reasons(self):
        _auth(self.tmp, "2999-01-01T00:00:00Z")
        for code, want in ((401, "auth-failed"), (403, "http-403"), (500, "http-500")):
            def _raise(req, timeout=None, code=code):
                raise urllib.error.HTTPError(req.full_url, code, "x", {}, None)
            with self.subTest(code=code), mock.patch.object(grok, "urlopen_no_redirect", _raise), \
                    mock.patch.object(grok, "_load_cookies", return_value=None):
                self.assertEqual(grok.fetch_grok_quota().unavailable_reason, want)

    def test_bad_json_and_malformed_fall_back(self):
        _auth(self.tmp, "2999-01-01T00:00:00Z")
        cases = ((b"not json", "bad-json"),
                 (json.dumps({"config": {"productUsage": 5}}).encode(), "parse-pending"))
        for body, want in cases:
            with self.subTest(want=want), mock.patch.object(grok, "urlopen_no_redirect", _ok(body)), \
                    mock.patch.object(grok, "_load_cookies", return_value=None):
                self.assertEqual(grok.fetch_grok_quota().unavailable_reason, want)

    def test_spent_budget_starts_no_request(self):
        _auth(self.tmp, "2999-01-01T00:00:00Z")
        ticks = iter([0.0] + [100.0] * 50)
        deadline = Deadline(grok._FETCH_BUDGET_S, clock=lambda: next(ticks))
        with mock.patch.object(grok, "urlopen_no_redirect", side_effect=AssertionError("request started")), \
                mock.patch.object(grok, "_load_cookies", return_value=None):
            res = grok.fetch_grok_quota(deadline)
        self.assertEqual(res.unavailable_reason, "timeout")

    def test_spent_budget_skips_cookie_acquisition(self):
        _auth(self.tmp, "2999-01-01T00:00:00Z")
        ticks = iter([0.0, 0.0] + [100.0] * 50)
        deadline = Deadline(grok._FETCH_BUDGET_S, clock=lambda: next(ticks))

        def _slow_fail(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 500, "x", {}, None)
        with mock.patch.object(grok, "urlopen_no_redirect", _slow_fail), \
                mock.patch.object(grok, "_load_cookies", side_effect=AssertionError("cookies read")):
            self.assertEqual(grok.fetch_grok_quota(deadline).unavailable_reason, "http-500")

    def test_cli_failure_falls_back_to_cookies(self):
        _auth(self.tmp, "2000-01-01T00:00:00Z")
        ok = grok.QuotaResult(label="grok", windows=[], details=["cookie"], unavailable_reason=None)
        with mock.patch.object(grok, "_load_cookies", return_value="c=1"), \
                mock.patch.object(grok, "urlopen_no_redirect", _ok(b"")), \
                mock.patch.object(grok, "_parse_grok_protobuf", return_value=ok):
            res = grok.fetch_grok_quota()
        self.assertEqual((res.unavailable_reason, res.details), (None, ["cookie"]))

    def test_deeply_nested_json_falls_back(self):
        deep = b"[" * 100000 + b"]" * 100000
        with open(os.path.join(self.tmp, "auth.json"), "wb") as fh:
            fh.write(deep)
        self.assertEqual(grok._load_grok_cli_token(), (None, "no-credentials"))
        _auth(self.tmp, "2999-01-01T00:00:00Z")
        with mock.patch.object(grok, "urlopen_no_redirect", _ok(deep)), \
                mock.patch.object(grok, "_load_cookies", return_value=None):
            self.assertEqual(grok.fetch_grok_quota().unavailable_reason, "bad-json")

    def test_cli_then_keyring_stays_inside_budget(self):
        """The CLI request burns 15s of the 18s budget. The keyring lookup
        reached through the cookie fallback gets the remaining 3s, not a fresh
        15s, and the next lookup is never started."""
        from quota_providers import browser_cookies as bc
        _auth(self.tmp, "2999-01-01T00:00:00Z")
        now = [0.0]
        deadline = Deadline(grok._FETCH_BUDGET_S, clock=lambda: now[0])
        timeouts = []

        def _slow_cli(req, timeout=None):
            now[0] += 15.0
            raise urllib.error.HTTPError(req.full_url, 500, "x", {}, None)

        def _run(cmd, timeout=None, **kw):
            timeouts.append(timeout)
            now[0] += timeout
            raise bc.subprocess.TimeoutExpired(cmd, timeout)

        def _chrome(deadline=None):
            self.assertIsNotNone(deadline)
            bc._linux_keyring_password("chrome", deadline)
            return None

        with mock.patch.dict(bc._LINUX_SECRET_LOOKUPS,
                             {"chrome": (("application", "chrome"), ("xdg:schema", "x"))}), \
                mock.patch.object(grok, "urlopen_no_redirect", _slow_cli), \
                mock.patch.object(grok, "_SESSION_PATH", os.path.join(self.tmp, "none.json")), \
                mock.patch.object(grok, "load_firefox_grok_cookies", return_value=None), \
                mock.patch.object(grok, "load_chrome_grok_cookies", _chrome), \
                mock.patch.object(bc.shutil, "which", return_value="/usr/bin/secret-tool"), \
                mock.patch.object(bc.subprocess, "run", _run):
            res = grok.fetch_grok_quota(deadline)
        self.assertEqual(timeouts, [3.0])
        self.assertEqual(res.unavailable_reason, "http-500")
        self.assertLessEqual(now[0], grok._FETCH_BUDGET_S)

    def test_null_issuer_is_rejected(self):
        _write_auth(self.tmp, {PUBLIC: {"key": "K", "expires_at": "2999-01-01T00:00:00Z",
                                        "oidc_issuer": None}})
        self.assertEqual(grok._load_grok_cli_token(), (None, "no-credentials"))

    def test_cookie_timeout_keeps_cli_reason(self):
        _auth(self.tmp, "2999-01-01T00:00:00Z")
        def _fail(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 500, "x", {}, None)
        with mock.patch.object(grok, "urlopen_no_redirect", _fail), \
                mock.patch.object(grok, "_load_cookies",
                                  side_effect=grok.ChromeCookieError("timeout")):
            self.assertEqual(grok.fetch_grok_quota().unavailable_reason, "http-500")

    def test_registry_gate_blocks_cli_when_disabled(self):
        _auth(self.tmp, "2999-01-01T00:00:00Z")
        with mock.patch.dict(os.environ, {"HERMES_QUOTA_GROK_ENABLED": "0"}), \
                mock.patch.object(grok, "_load_grok_cli_token", side_effect=AssertionError("read")):
            self.assertEqual(grok._fetch_grok_optin().unavailable_reason, "opt-in-disabled")


if __name__ == "__main__":
    unittest.main()
