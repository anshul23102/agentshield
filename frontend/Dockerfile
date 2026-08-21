# AgentShield dashboard image: build the static bundle, then serve it with
# nginx (proxying /api and /ws to the backend the same way vite.config.js's
# dev-server proxy does, since there's no dev server in a production build).
#
# VITE_API_KEY/VITE_ADMIN_KEY are baked into the JS bundle at BUILD time
# (Vite's import.meta.env works by string-replacing at build, there is no
# runtime env var reading for a static build) - pass them as --build-arg, not
# as a normal `docker run -e`. See docker-compose.yml at the repo root for
# why that creates a real bootstrap-ordering problem with this backend
# specifically, and the two-step workaround.
#
# NOTE ON VERIFICATION: never actually built with `docker build` - no Docker
# daemon was available where this was authored. `npm ci && npm run build`
# (the build stage's real work) is proven to work in this exact repo outside
# a container; the nginx serve stage and its proxy config have not been
# smoke-tested end to end. Verify before trusting it in a real deployment.

FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .

ARG VITE_API_KEY=""
ARG VITE_ADMIN_KEY=""
ENV VITE_API_KEY=${VITE_API_KEY}
ENV VITE_ADMIN_KEY=${VITE_ADMIN_KEY}
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://localhost/ || exit 1
