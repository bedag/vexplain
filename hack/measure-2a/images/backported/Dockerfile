# Debian 12 with libbrotli1 at the version in which the distribution fixed the vulnerability, 1.0.9-2+deb12u1.
# Debian backported the fix into 1.0.9, so the package carries the number of an upstream release that is
# affected, and carries the fix. The base image is named by its digest.
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
RUN apt-get update \
    && apt-get install --yes --no-install-recommends libbrotli1=1.0.9-2+deb12u1 \
    && rm -rf /var/lib/apt/lists/*
