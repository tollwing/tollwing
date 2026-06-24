include pkg/ebpf/bpf/Makefile
BIN_DIR := bin
.PHONY: all build demo sim test
all: build
build: bpf-all
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(BIN_DIR)/tollwing-agent-amd64 ./cmd/tollwing-agent
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o $(BIN_DIR)/tollwing-agent-arm64 ./cmd/tollwing-agent
demo:
	@go run ./test/sim/demo
sim:
	go test ./test/sim/... -count=1
test:
	go test ./pkg/... -count=1
