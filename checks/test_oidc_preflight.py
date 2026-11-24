import base64
import json
import unittest
from oidc_preflight import decode_claims, expected, validate_claims

ENV = {"GITHUB_REPOSITORY": "example/public-ci", "CI_REPO_ID": "123",
       "CI_OWNER_ID": "456", "GITHUB_SHA": "a" * 40,
       "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main"}

class PreflightTest(unittest.TestCase):
    def test_expected_identity(self):
        validate_claims(expected(ENV), ENV)

    def test_wrong_identity_fields(self):
        for key in expected(ENV):
            with self.subTest(key=key):
                claims = dict(expected(ENV), **{key: "wrong"})
                with self.assertRaises(ValueError):
                    validate_claims(claims, ENV)

    def test_untrusted_events_and_refs(self):
        for env in (dict(ENV, GITHUB_EVENT_NAME="pull_request"),
                    dict(ENV, GITHUB_REF="refs/heads/untrusted")):
            with self.assertRaises(ValueError):
                validate_claims(expected(env), env)

    def test_decode_is_not_signature_verification(self):
        payload = base64.urlsafe_b64encode(json.dumps(expected(ENV)).encode()).decode().rstrip("=")
        self.assertEqual(decode_claims("header." + payload + ".signature"), expected(ENV))
        for bad in ("", "a.b", "a..b", "x" * 24001):
            with self.assertRaises(ValueError):
                decode_claims(bad)

if __name__ == "__main__":
    unittest.main()
