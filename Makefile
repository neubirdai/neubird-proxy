IMAGE   ?= neubird-proxy
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test lint vuln fuzz bench image sbom check-config clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/neubird-proxy ./cmd/neubird-proxy

test:
	go test -race ./...

lint:
	go vet ./...
	test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

# Short fuzz pass over every target; CI runs this, run longer locally.
FUZZTIME ?= 15s
fuzz:
	for f in FuzzStringMasksEmbeddedPII FuzzNormalize FuzzJSON FuzzJSONStream FuzzSSE; do \
	  go test ./internal/redact -run '^$$' -fuzz "^$$f\$$" -fuzztime $(FUZZTIME) || exit 1; done

bench:
	go test ./internal/redact -run '^$$' -bench . -benchtime 3x

image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

# SPDX SBOM of the image, for MetLife's scan. Uses syft's container image
# so nothing extra is installed locally.
sbom: image
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock anchore/syft:v1.52.0 \
	  $(IMAGE):$(VERSION) -o spdx-json > sbom.spdx.json

# Validate a config without starting the proxy, e.g. before editing the
# ConfigMap: make check-config CONFIG=deploy/config.example.yaml
CONFIG ?= deploy/config.example.yaml
check-config: build
	NEUBIRD_PROXY_TOKEN=check-only-0123456789abcdef012345 NEUBIRD_PROXY_TOKEN_SERVICENOW=check-only-0123456789abcdef012345 APIM_SUBSCRIPTION_KEY=x ./bin/neubird-proxy -check -config $(CONFIG)

clean:
	rm -rf bin sbom.spdx.json
