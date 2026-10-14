# ok-file: docker.root-user, docker.latest-tag, docker.secret-in-env, docker.add-remote, ci.curl-pipe-shell
FROM node:22.11-alpine AS build
COPY . /app
RUN curl -fsSLo /tmp/tool.tgz https://downloads.acme.io/tool.tgz && echo "ab12  /tmp/tool.tgz" | sha256sum -c -
USER node
CMD ["node", "server.js"]
