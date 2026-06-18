# Multi-stage build for production-ready Vite dashboard

# Stage 1: Build the application
FROM node:18-slim AS builder

WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Install dependencies. Use `npm ci` when a lockfile is present (strict,
# reproducible) and fall back to `npm install` if the lockfile has not
# yet been committed. Both use --no-audit/--no-fund for quieter CI.
RUN if [ -f package-lock.json ]; then \
        npm ci --no-audit --no-fund; \
    else \
        npm install --no-audit --no-fund; \
    fi

# Copy application source
COPY . .

# Accept build arguments for Vite environment variables
# VITE_API_URL intentionally defaults to empty so the app uses relative "/api/v1"
# paths at runtime, which the nginx reverse proxy forwards to the backend.
# Override only for non-proxied setups: --build-arg VITE_API_URL=http://host:55000/api/v1
ARG VITE_API_URL=
ARG VITE_WS_URL=
ARG VITE_APP_NAME=SeceoKnight DLP
ARG VITE_APP_VERSION=2.0.0

# Set environment variables for build
ENV NODE_ENV=production
ENV VITE_API_URL=${VITE_API_URL}
ENV VITE_WS_URL=${VITE_WS_URL}
ENV VITE_APP_NAME=${VITE_APP_NAME}
ENV VITE_APP_VERSION=${VITE_APP_VERSION}

# Build application
RUN npm run build

# Production image with nginx
FROM nginx:alpine AS runner

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built files
COPY --from=builder /app/dist /usr/share/nginx/html

# Drop privileges — run nginx as the unprivileged `nginx` user that the
# official image already ships with. nginx:alpine's default /etc/nginx/
# nginx.conf has `user  nginx;` so the worker processes already drop
# privs, but the master runs as root. We rebind ports to 3000/ (unpriv)
# and run the master as `nginx` too.
#
# The /var/cache/nginx, /var/run, and /var/log/nginx directories must be
# writable by the nginx user — the base image already chowns them.
RUN touch /var/run/nginx.pid \
 && chown -R nginx:nginx /var/cache/nginx /var/run/nginx.pid /var/log/nginx /usr/share/nginx/html

USER nginx

# Expose the unprivileged port nginx.conf listens on.
EXPOSE 3000

# Run nginx in the foreground
CMD ["nginx", "-g", "daemon off;"]
