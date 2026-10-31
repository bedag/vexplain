# curl and its library, which link Brotli. The curl of Alpine 3.12 doesn't, so this image is on Alpine 3.13, the next
# release. It has the same Brotli version, 1.0.9, and the database flags brotli-libs in it the same way. libcurl.so.4
# needs libbrotlidec.so.1.
FROM alpine:3.13@sha256:469b6e04ee185740477efa44ed5bdd64a07bbdd6c7e5f5d169e540889597b911
RUN apk add --no-cache curl brotli-libs
