IMAGE   ?= neubird-proxy
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test lint image sbom check-config clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/neubird-proxy ./cmd/neubird-proxy

test:
	go test -race ./...

lint:
	go vet ./...
	test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

# SPDX SBOM of the image, for MetLife's scan. Uses syft's container image
# so nothing extra is installed locally.
sbom: image
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock anchore/syft:latest \
	  $(IMAGE):$(VERSION) -o spdx-json > sbom.spdx.json

# Validate a config without starting the proxy, e.g. before editing the
# ConfigMap: make check-config CONFIG=deploy/config.example.yaml
CONFIG ?= deploy/config.example.yaml
check-config: build
	NEUBIRD_PROXY_TOKEN=x APIM_SUBSCRIPTION_KEY=x ./bin/neubird-proxy -check -config $(CONFIG)

clean:
	rm -rf bin sbom.spdx.json
