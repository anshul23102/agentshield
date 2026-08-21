# Security Policy

## Supported Versions

AgentShield does not yet have tagged releases; only the `main` branch is
supported. Security fixes land there directly.

## Reporting a Vulnerability

Please do not open a public GitHub issue for security vulnerabilities.

Instead, use GitHub's private vulnerability reporting for this repository:

1. Go to the [Security tab](https://github.com/anshul23102/agentshield/security).
2. Click "Report a vulnerability".
3. Describe the issue, the affected component (backend, frontend, or SDK),
   and steps to reproduce.

This opens a private advisory visible only to the maintainer and you, so
the report is not disclosed publicly until a fix is available.

## What to Expect

- Acknowledgement of the report as soon as possible.
- An assessment of severity and, if confirmed, a fix developed in the
  private advisory before any public disclosure.
- Credit to the reporter in the advisory, unless anonymity is requested.

## Scope

In scope:
- The FastAPI backend (`backend/`), including the detection pipeline,
  authentication, and multi-tenant data isolation.
- The React dashboard (`frontend/`).
- The Python SDK (`sdk/`).

Out of scope:
- Vulnerabilities in third-party dependencies themselves (report those
  upstream; dependency updates are still welcome as PRs here).
- The demo/local-development bootstrap flow (`start.sh`, auto-generated
  bootstrap API keys), which is explicitly documented as unsuitable for
  production use.
