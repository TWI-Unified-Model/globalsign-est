ARG GO_VERSION=1.26.5

FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/estserver ./cmd/estserver

FROM alpine:3.22
RUN addgroup -S est && adduser -S -G est est
COPY --from=builder /out/estserver /usr/local/bin/estserver
USER est
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/estserver"]
CMD ["-config", "/etc/est/estserver.json"]