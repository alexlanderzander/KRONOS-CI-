"""Public, source-free OIDC identity preflight. No private credentials or code.

Decoded claims are diagnostic only. A future private broker must independently
verify JWT signature, expiration, audience and exact approved workflow identity.
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

AUDIENCE = "kronos-project-ci-v1"
WORKFLOW = ".github/workflows/preflight.yml"

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)

def decode_claims(assertion):
    if not isinstance(assertion, str) or len(assertion) > 24000:
        raise ValueError("invalid assertion")
    segments = assertion.split(".")
    if len(segments) != 3 or not all(segments):
        raise ValueError("invalid JWT shape")
    segment = segments[1]
    claims = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    if not isinstance(claims, dict):
        raise ValueError("invalid claims")
    return claims

def expected(env):
    return {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": AUDIENCE,
        "repository": env["GITHUB_REPOSITORY"],
        "repository_id": env["CI_REPO_ID"],
        "repository_owner_id": env["CI_OWNER_ID"],
        "ref": "refs/heads/main",
        "workflow_ref": env["GITHUB_REPOSITORY"] + "/" + WORKFLOW + "@refs/heads/main",
        "runner_environment": "github-hosted",
        "sha": env["GITHUB_SHA"],
        "workflow_sha": env["GITHUB_SHA"],
        "event_name": env["GITHUB_EVENT_NAME"],
    }

def validate_claims(claims, env):
    if env["GITHUB_EVENT_NAME"] not in ("push", "workflow_dispatch"):
        raise ValueError("untrusted event")
    if env["GITHUB_REF"] != "refs/heads/main":
        raise ValueError("untrusted ref")
    if any(str(claims.get(k, "")) != v for k, v in expected(env).items()):
        raise ValueError("OIDC identity mismatch")

def request_assertion(env, audience=AUDIENCE):
    endpoint = env["ACTIONS_ID_TOKEN_REQUEST_URL"]
    parsed = urllib.parse.urlsplit(endpoint)
    host = parsed.hostname or ""
    if (parsed.scheme != "https" or not host.endswith(".actions.githubusercontent.com")
            or parsed.username or parsed.password or parsed.fragment
            or parsed.port not in (None, 443)):
        raise ValueError("invalid token endpoint")
    endpoint += ("&" if parsed.query else "?") + urllib.parse.urlencode({"audience": audience})
    req = urllib.request.Request(endpoint, headers={
        "Authorization": "Bearer " + env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"],
        "Accept": "application/json",
    })
    with urllib.request.build_opener(NoRedirect).open(req, timeout=15) as response:
        raw = response.read(32001)
    if len(raw) > 32000:
        raise ValueError("oversized response")
    return json.loads(raw)["value"]

def main():
    validate_claims(decode_claims(request_assertion(os.environ)), os.environ)
    print("Kronos public OIDC identity preflight passed; no private source accessed")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Do not print token, decoded claims, response bodies or stack traces.
        print("Kronos public OIDC preflight failed", file=sys.stderr)
        raise SystemExit(1)
