# A binary with the Brotli decoder linked in statically, in an image that has nothing else: no package database,
# no shared library, no DT_NEEDED entry. A scan that works from packages and shared libraries can't see the copy.
# The build stage is Alpine 3.12, whose brotli-static package has the static libraries.
FROM alpine:3.12@sha256:c75ac27b49326926b803b9ed43bf088bc220d22556de1bc5f72d742c91398f69 AS build
RUN apk add --no-cache gcc musl-dev brotli-dev brotli-static
COPY main.c /src/main.c
RUN gcc -static -O1 -o /static-copy /src/main.c -lbrotlidec-static -lbrotlicommon-static

FROM scratch
COPY --from=build /static-copy /static-copy
ENTRYPOINT ["/static-copy"]
