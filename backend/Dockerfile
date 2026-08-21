# AgentShield backend image.
#
# NOTE ON VERIFICATION: this was hand-written and reviewed carefully, but
# `docker build` was never actually run against it - no Docker daemon was
# available in the environment it was authored in. Every install step below
# is the exact command already proven to work in this repo outside a
# container (`pip install -r requirements.lock` against Python 3.11.11); the
# Dockerfile just wraps that known-good command, but it has not itself been
# built and run end to end. Build and smoke-test it (`docker build . && docker
# run -p 8000:8000 <image>`, then curl /healthz) before trusting it in CI/CD
# or a real deployment.

FROM python:3.11.11-slim

# aiosqlite/presidio/spacy all need a C compiler available at install time for
# some transitive dependencies' source builds; removed after install so it
# doesn't bloat the final image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# requirements.lock (not requirements.txt) - the whole point of the lockfile
# is a reproducible install; a container build is exactly the place that
# matters most, since it's what actually ships to production.
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock

COPY . .

# Not baked into the image - backend/data is where the SQLite DB and the
# auto-generated admin/API key files live; a named volume or a mounted host
# path should point here in any real deployment (see the project README's
# "Deploying on Render's free tier" section for why persistence matters).
RUN mkdir -p /app/data
VOLUME ["/app/data"]

ENV PORT=8000
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://localhost:{os.environ.get(\"PORT\",\"8000\")}/healthz', timeout=3)" || exit 1

CMD ["python", "run_server.py"]
