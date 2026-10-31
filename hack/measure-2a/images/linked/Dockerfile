# The same libraries, and the brotli command, which links all three of them: /usr/bin/brotli needs
# libbrotlienc.so.1, libbrotlidec.so.1 and libbrotlicommon.so.1.
FROM alpine:3.12@sha256:c75ac27b49326926b803b9ed43bf088bc220d22556de1bc5f72d742c91398f69
RUN apk add --no-cache brotli-libs brotli
