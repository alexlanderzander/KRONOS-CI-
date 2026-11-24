"""Run a source-free synthetic CI job through the protected broker."""
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from oidc_preflight import NoRedirect, request_assertion

BASE = "https://kronos-ci-broker.evinsta9.workers.dev"
HTTP = urllib.request.build_opener(NoRedirect)

def digest(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def call(path, status, assertion=None, payload=None, method="POST"):
    headers = {"Accept": "application/json", "User-Agent": "Kronos-project-CI/1.0"}
    if assertion:
        headers["Authorization"] = "Bearer " + assertion
    if payload is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + "/v1/synthetic/" + path, headers=headers, method=method,
                                 data=json.dumps(payload).encode() if payload is not None else None)
    try:
        with HTTP.open(req, timeout=20) as response:
            code, raw, marker = response.status, response.read(2049), response.headers.get("X-Kronos-CI-Contract")
    except urllib.error.HTTPError as response:
        code, raw, marker = response.code, response.read(2049), response.headers.get("X-Kronos-CI-Contract")
    print("Synthetic " + path + ": HTTP " + str(code) + " expected " + str(status), flush=True)
    if code != status or len(raw) > 2048 or marker != "preflight-v1":
        raise RuntimeError("Unexpected broker response")
    return json.loads(raw)

def main():
    auth = request_assertion(os.environ)
    call("claim", 401)
    call("payload", 409, auth, method="GET")
    job = call("claim", 200, auth)
    if job["kind"] != "synthetic" or job["revision"] != os.environ["GITHUB_SHA"]:
        raise RuntimeError("Unexpected approved job")
    call("claim", 409, auth)
    obj = call("payload", 200, auth, method="GET")
    if digest(obj["payload"]) != obj["bundle_sha256"] or obj["bundle_sha256"] != job["bundle_sha256"]:
        raise RuntimeError("Invalid fixture")
    receipt = {k:job[k] for k in ("revision", "source_tree", "bundle_sha256")}
    receipt["evidence_sha256"] = "0" * 64
    call("result", 422, auth, receipt)
    receipt["evidence_sha256"] = digest("kronos-ci-synthetic-result-v1\n" + obj["payload"])
    if call("result", 200, auth, receipt) != {"accepted": True, "kind": "synthetic"}:
        raise RuntimeError("Receipt rejected")
    call("result", 409, auth, receipt)
    call("payload", 409, auth, method="GET")
    print("Synthetic job completed; digest verified and replay rejected. No private source used.", flush=True)

if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Synthetic broker job failed; private payloads and credentials are never printed.", file=sys.stderr)
        raise SystemExit(1)
