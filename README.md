# Kronos CI

Public project-specific CI infrastructure only. The private application repository remains the source of truth. This initial repository contains a source-free identity preflight and synthetic tests; it does not run private application tests or perform deployments.

## Security boundary

- No private source, portfolio data, credentials, production configuration, logs, build artifacts, or private caches are committed or uploaded here.
- Public pull requests run synthetic tests only and receive no OIDC permission.
- Trusted main-branch runs may request a short-lived project-specific OIDC assertion. The local claim checks are diagnostics, not cryptographic authentication.
- Any future private execution requires a separately reviewed broker or isolated private runner. A broker must independently validate issuer, signature, expiry, audience, exact repository/owner IDs, actor, workflow and approved run/commit; source transfer is disabled until this is tested.
- Public CI success is not private build, API, browser E2E, or release approval. Production release requires private revision-bound evidence.
- Use GitHub-hosted runners only for appropriate Kronos project development/testing under GitHub's current terms. No production data collection or unrelated compute.

Run synthetic tests locally with `python3 -m unittest discover -s checks -p 'test_*.py'`.
