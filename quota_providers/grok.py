"""Grok (X Premium / SuperGrok) quota fetcher — plugin standalone copy."""

from __future__ import annotations

import json
import os
import re
import tempfile
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional

from .base import Deadline, QuotaResult, QuotaWindow, build_unavailable, opt_in_flag, urlopen_no_redirect
from .browser_cookies import (
    ChromeCookieError,
    load_chrome_grok_cookies,
    load_firefox_grok_cookies,
)

_GROK_ENDPOINT = "https://grok.com/grok_api_v2.GrokBuildBilling/GetGrokCreditsConfig"
_REST_RATELIMITS_URL = "https://grok.com/rest/rate-limits"
_EMPTY_GRPCWEB_BODY = b"\x00\x00\x00\x00\x00"  # 0x00 frame + 4-byte len(0)
_BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
)

_SESSION_PATH = os.path.join(os.path.expanduser("~"), "grok_session.json")
_RAW_DEBUG_PATH = os.path.join(os.path.expanduser("~"), "grok_last_response.bin")


def _write_private_debug(path: str, raw: bytes) -> None:
    """Atomically replace a private debug file without following target symlinks."""
    parent = os.path.dirname(os.path.abspath(path)) or "."
    prefix = f".{os.path.basename(path)}."
    fd, temp_path = tempfile.mkstemp(prefix=prefix, dir=parent)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fd = -1
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_path, path)
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def _load_cookies() -> Optional[str]:
    try:
        with open(_SESSION_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        cookies = data.get("cookies") or data
        if isinstance(cookies, dict):
            cookies = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if cookies and str(cookies).strip():
            return str(cookies)
    except Exception:
        pass

    # Automatic local fallback: Firefox first (plaintext cookies), then
    # Chrome (encrypted). Only grok.com cookies are selected.
    firefox = load_firefox_grok_cookies()
    if firefox:
        return firefox
    return load_chrome_grok_cookies()


def _parse_grok_protobuf(raw: bytes) -> Optional[QuotaResult]:
    import struct

    msg = raw
    if msg[:1] == b"\x00" and len(msg) >= 5:
        length = int.from_bytes(msg[1:5], "big")
        if length and len(msg) >= 5 + length:
            msg = msg[5 : 5 + length]

    def parse(m):
        out = []
        i = 0
        while i < len(m):
            if i >= len(m):
                break
            key = m[i]
            i += 1
            fn = key >> 3
            wire = key & 0x07
            if wire == 0:
                v = 0
                s = 0
                while i < len(m):
                    b = m[i]
                    i += 1
                    v |= (b & 0x7F) << s
                    s += 7
                    if not (b & 0x80):
                        break
                out.append((fn, wire, v))
            elif wire == 2:
                ln = 0
                s = 0
                while i < len(m):
                    b = m[i]
                    i += 1
                    ln |= (b & 0x7F) << s
                    s += 7
                    if not (b & 0x80):
                        break
                d = m[i : i + ln]
                i += ln
                out.append((fn, wire, d))
            elif wire == 5:
                v = struct.unpack("<f", m[i : i + 4])[0]
                i += 4
                out.append((fn, wire, v))
            elif wire == 1:
                v = int.from_bytes(m[i : i + 8], "little")
                i += 8
                out.append((fn, wire, v))
            else:
                break
        return out

    top = parse(msg)
    if not top or top[0][0] != 1 or top[0][1] != 2:
        return None
    inner = parse(top[0][2])

    # Field map (decoded from a live capture, cross-checked against the
    # grok.com usage screen):
    #   fn1 float          — Weekly Limit % used (ABSENT = 0% used; the
    #                        grok.com panel renders "0% utilizado" when the
    #                        field is missing, e.g. free/unused accounts)
    #   fn4 / fn5 msg      — Weekly window start / reset (fn1 = epoch seconds)
    #   fn7 / fn8 msg      — typed breakdown of the SAME window: fn1 = kind,
    #                        fn2 float = % used. The panel draws these as the
    #                        legend under the single bar ("Grok Build 3%"), not
    #                        as extra meters — publishing them as windows showed
    #                        two quotas with the same % and reset date.
    #   fn11 / fn13 varint — flags with no counterpart in the grok.com UI; left
    #                        unreported on purpose. A fn11==1 → "Reset banked:
    #                        available" claim was shipped once and was wrong: the
    #                        Usage panel for the same payload showed only
    #                        "Weekly Limit 3% used / Resets …" and "Grok Build 3%".
    #                        Do not turn an unidentified field into a claim.
    used_percent: Optional[float] = None
    reset_epoch: Optional[int] = None

    def _sub_epoch(blob: bytes) -> Optional[int]:
        for sfn, sw, sv in parse(blob):
            if sfn == 1 and sw == 0 and isinstance(sv, int):
                return sv
        return None

    for fn, wire, v in inner:
        if fn == 1 and wire == 5:
            try:
                used_percent = float(v)
            except (TypeError, ValueError):
                pass
        elif fn == 5 and wire == 2:
            epoch = _sub_epoch(v)
            if epoch is not None and (reset_epoch is None or epoch > reset_epoch):
                reset_epoch = epoch

    if used_percent is None and reset_epoch is None:
        return None

    from datetime import datetime, timezone

    def _iso(epoch: Optional[int]) -> Optional[str]:
        if epoch is None:
            return None
        try:
            return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None

    windows: list[QuotaWindow] = []
    if used_percent is None and reset_epoch is not None:
        # Weekly window present but no usage field: the grok.com panel
        # renders this as "0% utilizado" (free/unused accounts).
        used_percent = 0.0
    if used_percent is not None or reset_epoch is not None:
        windows.append(
            QuotaWindow(
                label="Weekly Limit", used_percent=used_percent, reset_at=_iso(reset_epoch)
            )
        )

    if not windows:
        return None
    return QuotaResult(label="grok", windows=windows, details=[], unavailable_reason=None)


def _fetch_grok_rest(cookies: str, timeout: float = 15) -> Optional[QuotaResult]:
    """Fallback: per-model chat quota JSON endpoint (rest/rate-limits).

    This is a DIFFERENT meter from the billing gRPC above: chat queries per
    model on a rolling 2h window (e.g. ``10/10``), not the Weekly/Grok Build
    usage shown on the grok.com panel. Only reached when the gRPC probe fails.
    Plan name is not exposed anywhere in the Grok API (verified against both
    surfaces), so we never invent one.
    """
    body = json.dumps({"requestKind": "DEFAULT", "modelName": "grok-4"}).encode("utf-8")
    headers = {
        "accept": "*/*",
        "content-type": "application/json",
        "origin": "https://grok.com",
        "referer": "https://grok.com/?_s=usage",
        "user-agent": _BROWSER_UA,
        "cookie": cookies,
    }
    req = urllib.request.Request(_REST_RATELIMITS_URL, data=body, headers=headers, method="POST")
    try:
        with urlopen_no_redirect(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return build_unavailable("grok", "cloudflare-blocked" if e.code == 403 else "auth-failed")
        return None  # fall through to the gRPC probe
    except Exception:
        return None  # fall through to the gRPC probe

    windows: list[QuotaWindow] = []
    remaining = data.get("remainingQueries")
    total = data.get("totalQueries")
    if isinstance(remaining, (int, float)) and isinstance(total, (int, float)) and total > 0:
        used_pct = round(100.0 * (1.0 - float(remaining) / float(total)), 2)
        # No reset instant is reported: windowSizeSeconds is the LENGTH of a
        # rolling window, not an anchor, so any timestamp derived from it would
        # be invented (the panel's real reset comes from the gRPC path).
        windows.append(QuotaWindow(label="2h", used_percent=used_pct, reset_at=None))

    def _eff(block, label):
        if not isinstance(block, dict):
            return
        rem, tot = block.get("remainingQueries"), block.get("totalQueries")
        if isinstance(rem, (int, float)) and isinstance(tot, (int, float)) and tot > 0:
            windows.append(
                QuotaWindow(
                    label=label,
                    used_percent=round(100.0 * (1.0 - float(rem) / float(tot)), 2),
                )
            )

    _eff(data.get("lowEffortRateLimits"), "low effort")
    _eff(data.get("highEffortRateLimits"), "high effort")

    if not windows:
        return None
    return QuotaResult(label="grok", windows=windows, plan=None, unavailable_reason=None)


_CLI_BILLING_URL = "https://cli-chat-proxy.grok.com/v1/billing?format=credits"
# Only the public xAI OIDC login is sent to the public billing endpoint. The
# CLI stores enterprise/custom-IdP logins in the same file under other scopes;
# those belong to configured proxies and are skipped.
_CLI_PUBLIC_ISSUER = "https://auth.x.ai"
_CLI_TIMEOUT_S = 15.0
# The cache sweep waits REFRESH_BUDGET_S (20s); stay under it across the CLI
# billing call and the cookie fallback.
_FETCH_BUDGET_S = 18.0


def _grok_cli_auth_path() -> str:
    home = os.environ.get("GROK_HOME", "").strip() or os.path.join(os.path.expanduser("~"), ".grok")
    return os.path.join(home, "auth.json")


def _parse_expiry(value: object) -> Optional[datetime]:
    """Parse the CLI's RFC 3339 ``expires_at`` (nanosecond precision allowed).

    Returns an aware UTC datetime, or None when absent/unparseable.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    s = value.strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    m = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(?:\.(\d+))?([+-]\d{2}:?\d{2})?$", s)
    if not m:
        return None
    head, frac, off = m.group(1), m.group(2), m.group(3)
    # fromisoformat (3.9) takes at most 6 fractional digits.
    text = head + (f".{frac[:6].ljust(6, '0')}" if frac else "") + (off or "+00:00")
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc)


def _is_public_scope(scope: object, entry: dict) -> bool:
    issuer = entry.get("oidc_issuer")
    if isinstance(issuer, str) and issuer.strip():
        return issuer.strip().rstrip("/") == _CLI_PUBLIC_ISSUER
    return isinstance(scope, str) and scope.startswith(_CLI_PUBLIC_ISSUER + "::")


def _load_grok_cli_token() -> tuple[Optional[str], Optional[str]]:
    """Return (access_token, reason) from the Grok CLI login (``grok login``).

    The whole auth document is parsed, but only the access-token field of a
    public xAI scope is used. The refresh token is never sent anywhere by the
    plugin and the file is never written. Expired -> ``reauth-required``;
    a token with no parseable expiry is tried and the server decides.
    """
    try:
        with open(_grok_cli_auth_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None, "no-credentials"
    if not isinstance(data, dict):
        return None, "no-credentials"
    now = datetime.now(timezone.utc)
    expired = False
    for scope, entry in data.items():
        if not isinstance(entry, dict) or not _is_public_scope(scope, entry):
            continue
        key = entry.get("key")
        if not isinstance(key, str) or not key.strip():
            continue
        when = _parse_expiry(entry.get("expires_at"))
        if when is not None and when <= now:
            expired = True
            continue
        return key.strip(), None
    return None, ("reauth-required" if expired else "no-credentials")


def _num(value: object) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _parse_cli_billing(data: object) -> Optional[QuotaResult]:
    """Map the CLI ``/billing?format=credits`` JSON (same meter as the
    grok.com usage panel: weekly credit %, per-product legend).

    Returns None for any shape it does not recognise so the caller can fall
    back; never raises on malformed input.
    """
    if not isinstance(data, dict):
        return None
    cfg = data.get("config")
    if not isinstance(cfg, dict):
        return None
    pct = _num(cfg.get("creditUsagePercent"))
    _period = cfg.get("currentPeriod")
    period: dict = _period if isinstance(_period, dict) else {}
    reset = period.get("end") or cfg.get("billingPeriodEnd")
    reset = reset if isinstance(reset, str) and reset else None
    label = {
        "USAGE_PERIOD_TYPE_WEEKLY": "Weekly Limit",
        "USAGE_PERIOD_TYPE_MONTHLY": "Monthly Limit",
        "USAGE_PERIOD_TYPE_DAILY": "Daily Limit",
    }.get(str(period.get("type") or ""), "Limit")
    windows: list[QuotaWindow] = []
    if pct is not None:
        windows.append(QuotaWindow(label=label, used_percent=pct, reset_at=reset))
    details: list[str] = []
    products = cfg.get("productUsage")
    if isinstance(products, list):
        for item in products:
            if not isinstance(item, dict):
                continue
            used = _num(item.get("usagePercent"))
            if used is None:
                continue
            name = str(item.get("product") or "?")
            name = {"GrokBuild": "Grok Build"}.get(name, name)
            details.append(f"{name}: {used:g}% used")

    def _val(k: str) -> Optional[float]:
        v = cfg.get(k)
        return _num(v.get("val")) if isinstance(v, dict) else None

    cap = _val("onDemandCap")
    if cap is not None and cap > 0:
        details.append(f"On-demand: {_val('onDemandUsed') or 0:g} / {cap:g}")
    bal = _val("prepaidBalance")
    if bal is not None and bal > 0:
        details.append(f"Prepaid balance: {bal:g}")
    if not windows and not details:
        return None
    return QuotaResult(label="grok", windows=windows, details=details, unavailable_reason=None)


def _fetch_grok_cli(deadline: Deadline) -> Optional[QuotaResult]:
    """Primary source on headless boxes: the Grok CLI OIDC login.

    Returns None when there is no usable CLI login so the cookie path runs.
    """
    token, reason = _load_grok_cli_token()
    if not token:
        return build_unavailable("grok", reason) if reason == "reauth-required" else None
    timeout = deadline.slice(_CLI_TIMEOUT_S)
    if timeout <= 0:
        return build_unavailable("grok", "timeout")
    req = urllib.request.Request(
        _CLI_BILLING_URL,
        headers={"authorization": f"Bearer {token}", "accept": "application/json",
                 "user-agent": "hermes-quota-plugin"},
        method="GET",
    )
    try:
        with urlopen_no_redirect(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        # Only 401 proves the credential is bad; 403 may be policy/edge.
        return build_unavailable("grok", "auth-failed" if e.code == 401 else f"http-{e.code}")
    except Exception as e:
        return build_unavailable("grok", f"fetch-error:{type(e).__name__}")
    try:
        data = json.loads(raw)
    except ValueError:
        return build_unavailable("grok", "bad-json")
    return _parse_cli_billing(data) or build_unavailable("grok", "parse-pending")


def fetch_grok_quota(deadline: Optional[Deadline] = None) -> QuotaResult:
    deadline = deadline or Deadline(_FETCH_BUDGET_S)
    cli = _fetch_grok_cli(deadline)
    if cli is not None and cli.unavailable_reason is None:
        return cli
    try:
        cookies = _load_cookies()
    except ChromeCookieError as exc:
        return build_unavailable("grok", exc.reason)
    if not cookies:
        return cli if cli is not None else build_unavailable("grok", "no-session-cookies")

    # Primary: the billing gRPC — this is the "Weekly Limit" + "Grok Build"
    # usage screen (percent used + reset). Verified 1:1 against the grok.com
    # usage panel: same percentages, same reset instant. Fields the panel does
    # not render (fn11/fn13 flags) are deliberately not reported.
    headers = {
        "accept": "*/*",
        "content-type": "application/grpc-web+proto",
        "origin": "https://grok.com",
        "referer": "https://grok.com/?_s=usage",
        "user-agent": _BROWSER_UA,
        "x-grpc-web": "1",
        "x-user-agent": "connect-es/2.1.1",
        "cache-control": "no-cache",
        "pragma": "no-cache",
        "cookie": cookies,
    }
    req = urllib.request.Request(_GROK_ENDPOINT, data=_EMPTY_GRPCWEB_BODY, headers=headers, method="POST")
    timeout = deadline.slice(15)
    if timeout <= 0:
        return cli if cli is not None else build_unavailable("grok", "timeout")
    try:
        with urlopen_no_redirect(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return build_unavailable("grok", "cloudflare-blocked" if e.code == 403 else "auth-failed")
        return build_unavailable("grok", f"http-{e.code}")
    except Exception as e:
        return build_unavailable("grok", f"fetch-error:{type(e).__name__}")
    if os.environ.get("HERMES_QUOTA_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}:
        try:
            _write_private_debug(_RAW_DEBUG_PATH, raw)
        except Exception:
            pass
    result = _parse_grok_protobuf(raw)
    if result is not None:
        return result

    # Fallback: the per-model chat quota (rest/rate-limits). NOTE: this is a
    # DIFFERENT meter — chat queries per model on a rolling 2h window, not the
    # Build/weekly usage the panel shows. Only used when the gRPC parse fails.
    if deadline.expired():
        return build_unavailable("grok", "timeout")
    rest = _fetch_grok_rest(cookies, timeout=deadline.slice(15))
    if rest is not None:
        return rest
    return build_unavailable("grok", "parse-pending")


from .registry import register as _register  # noqa: E402

# Grok is opt-in: reads browser cookies (Firefox grok.com, then Chrome on
# macOS). Disabled by default; enable with:
#   hermes config set plugins.entries.quota.settings.grokEnabled true
import os as _os

# Resolve opt-in from plugin config (set via `hermes config set ...`), falling
# back to the HERMES_QUOTA_GROK_ENABLED env var. Config wins so the UI toggle
# and CLI config are the single source of truth.
def _grok_setting(key: str, env: str) -> bool:
    val = _os.environ.get(env, "").strip().lower()
    if val in {"1", "true", "yes", "on"}:
        return True
    if val in {"0", "false", "no", "off"}:
        return False
    try:
        from hermes_cli.config import load_config_readonly
        cfg = load_config_readonly() or {}
        plugins = cfg.get("plugins") if isinstance(cfg, dict) else None
        entries = plugins.get("entries") if isinstance(plugins, dict) else None
        entry = entries.get("quota") if isinstance(entries, dict) else None
        if isinstance(entry, dict):
            settings = entry.get("settings")
            if isinstance(settings, dict) and key in settings:
                return opt_in_flag(settings.get(key))
    except Exception:
        pass
    return False


def _grok_enabled() -> bool:
    return _grok_setting("grokEnabled", "HERMES_QUOTA_GROK_ENABLED")


def _fetch_grok_optin() -> Optional["QuotaResult"]:
    if not _grok_enabled():
        return build_unavailable("grok", "opt-in-disabled")
    return fetch_grok_quota()


_register("grok")(_fetch_grok_optin)
