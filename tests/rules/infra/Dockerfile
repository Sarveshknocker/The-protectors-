# ruleid: docker.root-user, docker.latest-tag
FROM node:latest
# ruleid: docker.secret-in-env
ENV API_TOKEN=abc123def456
# ruleid: docker.add-remote
ADD https://downloads.acme.io/tool.tgz /opt/
# ruleid: ci.curl-pipe-shell
RUN curl -fsSL https://get.acme.io/install.sh | sh
CMD ["node", "server.js"]
