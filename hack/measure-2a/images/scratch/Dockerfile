# An image with no packages at all: one static program that waits, and nothing else. A Deployment needs a process
# that stays alive, and the image has no sleep.
FROM alpine:3.12@sha256:c75ac27b49326926b803b9ed43bf088bc220d22556de1bc5f72d742c91398f69 AS build
RUN apk add --no-cache gcc musl-dev
COPY pause.c /src/pause.c
RUN gcc -static -O1 -o /pause /src/pause.c

FROM scratch
COPY --from=build /pause /pause
ENTRYPOINT ["/pause"]
