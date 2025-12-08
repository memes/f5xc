# syntax=docker/dockerfile:1
FROM alpine:3.23.0 AS ca
RUN apk --no-cache add ca-certificates-bundle=20251003-r0

FROM scratch
COPY --from=ca /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY unseal /
# Default entrypoint will run the unseal utility; override as necessary
ENTRYPOINT ["/unseal"]
