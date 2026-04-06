BINARY    := honeybadger
BUILD_DIR := ./bin
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS   := -ldflags "-s -w -X main.Version=$(VERSION)"
GOFLAGS   := CGO_ENABLED=0
REPRO     := -trimpath -buildvcs=false

.PHONY: build cross test self-check self-check-bootstrap clean docker release-dry

build:
	@mkdir -p $(BUILD_DIR)
	$(GOFLAGS) go build $(LDFLAGS) $(REPRO) -o $(BUILD_DIR)/$(BINARY) ./cmd/honeybadger

cross:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux  GOARCH=arm64       $(GOFLAGS) go build $(LDFLAGS) $(REPRO) -o $(BUILD_DIR)/$(BINARY)-linux-arm64  ./cmd/honeybadger
	GOOS=linux  GOARCH=arm GOARM=7 $(GOFLAGS) go build $(LDFLAGS) $(REPRO) -o $(BUILD_DIR)/$(BINARY)-linux-armv7  ./cmd/honeybadger
	GOOS=linux  GOARCH=amd64       $(GOFLAGS) go build $(LDFLAGS) $(REPRO) -o $(BUILD_DIR)/$(BINARY)-linux-amd64  ./cmd/honeybadger
	GOOS=darwin GOARCH=arm64       $(GOFLAGS) go build $(LDFLAGS) $(REPRO) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 ./cmd/honeybadger
	GOOS=darwin GOARCH=amd64       $(GOFLAGS) go build $(LDFLAGS) $(REPRO) -o $(BUILD_DIR)/$(BINARY)-darwin-amd64 ./cmd/honeybadger
	@echo "All targets built"

android-install:
	CGO_ENABLED=0 go install github.com/famclaw/honeybadger/cmd/honeybadger@latest

test:
	go test ./... -v

self-check: build
	./$(BUILD_DIR)/$(BINARY) scan github.com/famclaw/honeybadger --paranoia strict
	@echo "Self-check passed"

self-check-bootstrap: build
	./$(BUILD_DIR)/$(BINARY) scan github.com/famclaw/honeybadger --paranoia minimal
	@echo "Self-check (bootstrap) passed"

docker:
	docker buildx build --build-arg VERSION=$(VERSION) -t honeybadger:$(VERSION) .

release-dry:
	goreleaser release --snapshot --clean

clean:
	rm -rf $(BUILD_DIR) dist
