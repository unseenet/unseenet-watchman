# unseenet-watchman in a container: the spam-report issuer and labeller (UN-RFC 0045,
# 0053) on the node image (core, chiavdf, Tor, tini). Vault, config and state in /data.
#
#   docker run --rm -v watchman:/data ghcr.io/unseenet/watchman            # writes an example watchman.toml
#   docker run --rm -v watchman:/data -e UNSEENET_VAULT_PASSPHRASE=... ghcr.io/unseenet/watchman init
#   docker run -d --name watchman -v watchman:/data -e UNSEENET_VAULT_PASSPHRASE=... ghcr.io/unseenet/watchman
#
# See the docs ("In Docker") and compose.yaml.
ARG NODE_IMAGE=ghcr.io/unseenet/node:latest

FROM ${NODE_IMAGE} AS build
USER root
# a core newer than the image's (from git, before a release) builds chiavdf here
RUN apk add --no-cache gcc g++ musl-dev python3-dev libffi-dev cmake make gmp-dev git
ENV BUILD_VDF_CLIENT=N
COPY pyproject.toml README.md LICENSE NOTICE watchman.example.toml /src/
COPY src /src/src
RUN /opt/unseenet/bin/pip install --no-cache-dir "/src[lingua]" \
 && find /opt/unseenet -name __pycache__ -type d -prune -exec rm -rf {} +

FROM ${NODE_IMAGE}
USER root
COPY --from=build /opt/unseenet /opt/unseenet
COPY watchman.example.toml /opt/unseenet-watchman/watchman.example.toml
COPY docker/entrypoint.sh /usr/local/bin/unseenet-watchman-entrypoint
RUN chmod 755 /usr/local/bin/unseenet-watchman-entrypoint
ENV UNSEENET_DATA=/data
VOLUME /data
HEALTHCHECK NONE
LABEL org.opencontainers.image.title="Unseenet watchman" \
      org.opencontainers.image.description="Signed spam reports and content labels for Unseenet, that readers choose to follow" \
      org.opencontainers.image.source="https://github.com/unseenet/unseenet-watchman" \
      org.opencontainers.image.url="https://unseenet.org/watchman/" \
      org.opencontainers.image.licenses="Apache-2.0"
ENTRYPOINT ["/sbin/tini", "--", "unseenet-watchman-entrypoint"]
CMD []
