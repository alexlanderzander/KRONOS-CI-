"""Exercise a source-disabled broker with genuine GitHub OIDC assertions."""
import json
import os
import sys
import urllib.error
import urllib.request
from oidc_preflight import NoRedirect, request_assertion, decode_claims, AUDIENCE
import time

BASE = "https://kronos-ci-broker.evinsta9.workers.dev"
HTTP = urllib.request.build_opener(NoRedirect)

def check(path, code, assertion=None, method="POST", expected=None, label="probe"):
    headers = {"Accept": "application/json", "User-Agent": "Kronos-project-CI/1.0"}
    if assertion is not None:
        headers["Authorization"] = "Bearer " + assertion
    request = urllib.request.Request(BASE + path, headers=headers, method=method)
    try:
        with HTTP.open(request, timeout=20) as response:
            status, raw, headers_out = response.status, response.read(2049), response.headers
    except urllib.error.HTTPError as response:
        status, raw, headers_out = response.code, response.read(2049), response.headers
    print(label + ': HTTP ' + str(status) + ' expected ' + str(code), flush=True)
    print("Response contract: " + json.dumps({"broker": headers_out.get("X-Kronos-CI-Contract") == "preflight-v1", "json": "application/json" in headers_out.get("Content-Type", ""), "challenge": headers_out.get("cf-mitigated") == "challenge", "accessRedirect": bool(headers_out.get("Location"))}), flush=True)
    if status != code or len(raw) > 2048 or headers_out.get("X-Kronos-CI-Contract") != "preflight-v1":
        raise RuntimeError("unexpected status or response length")
    if expected is not None and json.loads(raw) != expected:
        raise RuntimeError("unexpected preflight contract")

def main():
    assertion = request_assertion(os.environ)
    c = decode_claims(assertion)
    repo = os.environ['GITHUB_REPOSITORY']
    owner, name = repo.split('/')
    sub = 'repo:' + owner + '@' + os.environ['CI_OWNER_ID'] + '/' + name + '@' + os.environ['CI_REPO_ID'] + ':ref:refs/heads/main'
    now = int(time.time())
    print('Claim policy diagnostics (booleans only):', json.dumps({'immutableSubject': c.get('sub') == sub, 'actor': str(c.get('actor_id')) == os.environ['CI_OWNER_ID'], 'public': c.get('repository_visibility') == 'public', 'branch': c.get('ref_type') == 'branch', 'runIdentity': bool(c.get('run_id') and c.get('run_attempt') and c.get('jti')), 'timeWindow': all(isinstance(c.get(k), int) for k in ('iat','nbf','exp')) and c['exp'] > now and c['exp'] - c['iat'] <= 900}, sort_keys=True), flush=True)
    wrong_aud = request_assertion(os.environ, AUDIENCE + "-negative-test")
    parts = assertion.split(".")
    parts[2] = ("B" if parts[2][0] == "A" else "A") + parts[2][1:]
    check("/v1/preflight", 401, label="anonymous")
    check("/v1/preflight", 401, "not-a-jwt", label="malformed")
    check("/v1/preflight", 401, ".".join(parts), label="invalid signature")
    check("/v1/preflight", 403, wrong_aud, label="wrong audience")
    check("/v1/preflight", 200, assertion, expected={"status": "ok", "sourceAccess": False}, label="authorized")
    check("/v1/source/0", 404, assertion, method="GET", label="disabled route")
    check("/v1/result", 404, assertion, label="disabled result")
    check("/v1/job", 404, assertion, method="GET")
    print("Broker preflight passed: signature, audience, anonymous denial and disabled source/result/job routes.")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Broker preflight failed; no token or response body emitted.", file=sys.stderr)
        raise SystemExit(1)
