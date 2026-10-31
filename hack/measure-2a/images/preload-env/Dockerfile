# The decoder library, preloaded by the image's own configuration: no ELF file needs it, and no file names
# it, but every process of the image loads it.
FROM alpine:3.12@sha256:c75ac27b49326926b803b9ed43bf088bc220d22556de1bc5f72d742c91398f69
RUN apk add --no-cache brotli-libs
ENV LD_PRELOAD=/usr/lib/libbrotlidec.so.1
