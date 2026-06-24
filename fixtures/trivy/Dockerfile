# WatsonSec fixture — intentionally insecure Dockerfile for Trivy adapter testing.
# DO NOT use in production.

# Trivy should flag: using 'latest' tag (no pinned digest)
FROM node:latest

# Trivy should flag: running as root (no USER instruction)
# Trivy should flag: apt-get without version pinning

RUN apt-get update && apt-get install -y curl wget

# Trivy should flag: hardcoded secret
ENV SECRET_KEY="hardcoded-secret-do-not-use-FAKEFAKE"
ENV AWS_ACCESS_KEY_ID="AKIAFAKEFAKEFAKEFAKE"

WORKDIR /app
COPY . .
RUN npm install

# Trivy misconfiguration: exposing privileged port
EXPOSE 80

# Missing: no USER instruction — container runs as root
CMD ["node", "index.js"]
