# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/neubird-proxy ./cmd/neubird-proxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/neubird-proxy /neubird-proxy
USER nonroot:nonroot
EXPOSE 8443 9090
ENTRYPOINT ["/neubird-proxy"]
CMD ["-config", "/etc/neubird-proxy/config.yaml"]
