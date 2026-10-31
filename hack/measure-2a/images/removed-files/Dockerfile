# The package is installed, and a later layer deletes every file that it owns. The package database still
# lists brotli-libs, and none of its files is left in the final filesystem.
FROM alpine:3.12@sha256:c75ac27b49326926b803b9ed43bf088bc220d22556de1bc5f72d742c91398f69
RUN apk add --no-cache brotli-libs
RUN rm /usr/lib/libbrotlicommon.so.1 /usr/lib/libbrotlicommon.so.1.0.9 \
        /usr/lib/libbrotlidec.so.1 /usr/lib/libbrotlidec.so.1.0.9 \
        /usr/lib/libbrotlienc.so.1 /usr/lib/libbrotlienc.so.1.0.9
