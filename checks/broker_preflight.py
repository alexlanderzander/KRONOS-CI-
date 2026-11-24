"""Exercise a source-disabled broker with genuine GitHub OIDC assertions."""
import json
import os
import sys
import urllib.error
import urllib.request
from oidc_preflight import NoRedirect, request_assertion, AUDIENCE

BASE = "https://kronos-ci-broker.evinsta9.workers.dev"
HTTP = urllib.request.build_opener(NoRedirect)

def check(path, code, assertion=None, method="POST", expected=None):
    headers = {"Accept": "application/json"}
    if assertion is not None:
        headers["Authorization"] = "Bearer " + assertion
    request = urllib.request.Request(BASE + path, headers=headers, method=method)
    try:
        with HTTP.open(request, timeout=20) as response:
            status, raw = response.status, response.read(2049)
    except urllib.error.HTTPError as response:
        status, raw = response.code, response.read(2049)
    if status != code or len(raw) > 2048:
        raise RuntimeError("unexpected status or response length")
    if expected is not None and json.loads(raw) != expected:
        raise RuntimeError("unexpected preflight contract")

def main():
    assertion = request_assertion(os.environ)
    wrong_aud = request_assertion(os.environ, AUDIENCE + "-negative-test")
    parts = assertion.split(".")
    parts[2] = ("B" if parts[2][0] == "A" else "A") + parts[2][1:]
    check("/v1/preflight", 401)
    check("/v1/preflight", 401, "not-a-jwt")
    check("/v1/preflight", 401, ".".join(parts))
    check("/v1/preflight", 403, wrong_aud)
    check("/v1/preflight", 200, assertion, expected={"status": "ok", "sourceAccess": False})
    check("/v1/source/0", 404, assertion, method="GET")
    check("/v1/result", 404, assertion)
    check("/v1/job", 404, assertion, method="GET")
    print("Broker preflight passed: signature, audience, anonymous denial and disabled source/result/job routes.")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Broker preflight failed; no token or response body emitted.", file=sys.stderr)
        raise SystemExit(1)
