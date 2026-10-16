# The deploy workflow's self-test image. Nothing is pulled: a dry run has no
# ECR login, and this proves the build step without a network or a registry.
FROM scratch
ARG GIT_SHA=unknown
LABEL org.opencontainers.image.revision=$GIT_SHA
COPY test/deploy/Dockerfile /Dockerfile
