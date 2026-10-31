# Python, with a script that finds the Brotli decoder by its bare name, "brotlidec", and loads it. No ELF file
# needs the library, and the script names neither libbrotlidec.so.1 nor libbrotlidec.so, so only the bare
# name leads to it.
FROM alpine:3.12@sha256:c75ac27b49326926b803b9ed43bf088bc220d22556de1bc5f72d742c91398f69
RUN apk add --no-cache python3 brotli-libs
COPY load-brotli.py /app/load-brotli.py
