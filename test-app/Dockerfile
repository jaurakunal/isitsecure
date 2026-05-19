# VULNERABILITY: Multiple Docker security issues
# Scanner: docker_scanner (#33)

# Uses latest tag (unpinned)
FROM node:latest

# Runs as root (no USER directive)
WORKDIR /app

# Copies .env file into image
COPY . .
COPY .env .env

RUN npm install
RUN npm run build

# Exposes unnecessary port
EXPOSE 3000
EXPOSE 5432

CMD ["npm", "start"]
