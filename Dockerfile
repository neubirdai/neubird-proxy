# syntax=docker/dockerfile:1
# Base images are pinned by digest so a rebuild cannot silently pick up a
# different image. Bump both deliberately (see README, Supply chain).
FROM golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/neubird-proxy ./cmd/neubird-proxy

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/neubird-proxy /neubird-proxy
USER nonroot:nonroot
EXPOSE 8443 9090
ENTRYPOINT ["/neubird-proxy"]
CMD ["-config", "/etc/neubird-proxy/config.yaml"]
