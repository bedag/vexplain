# Alpine 3.12 with the Brotli libraries installed and nothing that uses them: the package database lists
# brotli-libs, and no other file of the image needs libbrotlidec.so.1, libbrotlienc.so.1 or
# libbrotlicommon.so.1, or names a Brotli library. The base image is named by its digest, so that the image never
# changes.
FROM alpine:3.12@sha256:c75ac27b49326926b803b9ed43bf088bc220d22556de1bc5f72d742c91398f69
RUN apk add --no-cache brotli-libs
