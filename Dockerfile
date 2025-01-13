FROM alpine:3.21.2 as ca
RUN apk --no-cache add ca-certificates-bundle=20241010-r0

FROM scratch
COPY --from=ca /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY unseal /
# Default entrypoint will run the unseal utility; override as necessary
ENTRYPOINT ["/unseal"]
