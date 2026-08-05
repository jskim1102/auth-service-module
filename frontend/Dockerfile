# Multi-stage demo-frontend image: build the Vite SPA, serve the static dist via nginx.
# Container listens on 80 (compose maps ${FRONTEND_PORT}:80).

# --- build stage -------------------------------------------------------------
FROM node:20-alpine AS build
WORKDIR /app

# vite.config.js calls loadEnv('..') for FRONTEND_PORT and THROWS if it's unset.
# The parent .env is NOT in this build context (context = ./frontend), so supply
# the value as a build arg → process.env, which loadEnv also reads. It only feeds
# vite's dev/preview server port (irrelevant to the static build), but the config
# refuses to run without it.
ARG FRONTEND_PORT=80
ENV FRONTEND_PORT=$FRONTEND_PORT

COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build   # → /app/dist

# --- serve stage -------------------------------------------------------------
FROM nginx:alpine AS serve
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
