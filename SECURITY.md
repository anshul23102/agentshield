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

## Deploying Publicly: Read This First

If you fork this and deploy your own instance somewhere reachable by
strangers (a portfolio/interview demo, for example), these are not optional:

1. **Never set `VITE_ADMIN_KEY` as an environment variable on the platform
   building your public frontend** (Vercel, Netlify, etc.). The admin key
   can mint unlimited API keys, wipe session data, and clear caches -
   nothing a public visitor should be able to trigger. As of this repo's
   current code, `frontend/src/utils/api.js` gates this key behind
   `import.meta.env.DEV`, which Vite statically resolves to `false` in any
   `vite build` output - so even if you *do* set that variable on your
   hosting platform, a production build will not embed it. Treat that as a
   safety net, not permission to set it anyway.
2. **`VITE_API_KEY` is expected to be public** in a deployed build - it's
   what lets your own dashboard call your own backend from a stranger's
   browser. Use a dedicated key for this (`create_api_key` with its own
   label), not a key you also use for anything sensitive, and keep the
   backend's rate limit (`AGENTSHIELD_RATE_LIMIT_PER_MINUTE`, default 120/min
   per key) low enough that abuse of a leaked public demo key stays cheap.
3. **Set `AGENTSHIELD_ALLOWED_ORIGINS`** on the backend to your actual
   frontend origin instead of leaving it at the default `*`.
4. **Rotate the admin key and any LLM provider keys** if you ever suspect a
   deployment's environment variables were exposed (a misconfigured CI log,
   a screen-shared terminal, etc.) - both are read fresh from the
   environment on process start, so a rotation just needs a redeploy.
5. Free-tier hosts (Render's free web service, for example) wipe the local
   filesystem on every redeploy/cold-restart, which regenerates the admin
   key each time (see `README.md`'s Render section) - don't assume an admin
   key from a previous deploy is still valid, and don't rely on the
   filesystem being a secrets store even locally.
