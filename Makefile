VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "v0.1.0-dev")
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: test vet build release-bins clean

test:
	go test -count=1 -v ./...

vet:
	go vet ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/sandbox-check ./cmd/sandbox-check

release-bins:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/sandbox-check-linux-amd64 ./cmd/sandbox-check
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/sandbox-check-linux-arm64 ./cmd/sandbox-check
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/sandbox-check-darwin-amd64 ./cmd/sandbox-check
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/sandbox-check-darwin-arm64 ./cmd/sandbox-check
	cd dist && shasum -a 256 sandbox-check-* > checksums.txt

clean:
	rm -f bin/sandbox-check
