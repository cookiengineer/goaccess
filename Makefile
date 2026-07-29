# GoAccess Makefile
# Build targets for the main binary and cross-compiled reverse shell payloads.

GO           := go
GOFLAGS      := CGO_ENABLED=0
LDFLAGS      := -ldflags="-s -w"
OUTPUT_DIR   := bin
PAYLOAD_DIR  := payload

.PHONY: all build payloads test lint clean

all: build

build:
	$(GOFLAGS) $(GO) build $(LDFLAGS) -o $(OUTPUT_DIR)/goaccess ./cmds/goaccess

payloads: payloads-arm payloads-arm64 payloads-mips payloads-mipsle payloads-mips64 payloads-x86 payloads-x86_64

payloads-arm:
	GOOS=linux GOARCH=arm GOARM=5 $(GOFLAGS) $(GO) build $(LDFLAGS) -o $(PAYLOAD_DIR)/arm/reverse_tcp ./cmds/rshell
	GOOS=linux GOARCH=arm GOARM=5 $(GOFLAGS) $(GO) build $(LDFLAGS) -o $(PAYLOAD_DIR)/arm/bind_tcp ./cmds/rshell

payloads-arm64:
	GOOS=linux GOARCH=arm64 $(GOFLAGS) $(GO) build $(LDFLAGS) -o $(PAYLOAD_DIR)/arm64/reverse_tcp ./cmds/rshell
	GOOS=linux GOARCH=arm64 $(GOFLAGS) $(GO) build $(LDFLAGS) -o $(PAYLOAD_DIR)/arm64/bind_tcp ./cmds/rshell

payloads-mips:
	GOOS=linux GOARCH=mips GOMIPS=softfloat $(GOFLAGS) $(GO) build $(LDFLAGS) -o $(PAYLOAD_DIR)/mips/reverse_tcp ./cmds/rshell
	GOOS=linux GOARCH=mips GOMIPS=softfloat $(GOFLAGS) $(GO) build $(LDFLAGS) -o $(PAYLOAD_DIR)/mips/bind_tcp ./cmds/rshell

payloads-mipsle:
	GOOS=linux GOARCH=mipsle GOMIPS=softfloat $(GOFLAGS) $(GO) build $(LDFLAGS) -o $(PAYLOAD_DIR)/mipsle/reverse_tcp ./cmds/rshell
	GOOS=linux GOARCH=mipsle GOMIPS=softfloat $(GOFLAGS) $(GO) build $(LDFLAGS) -o $(PAYLOAD_DIR)/mipsle/bind_tcp ./cmds/rshell

payloads-mips64:
	GOOS=linux GOARCH=mips64 GOMIPS=softfloat $(GOFLAGS) $(GO) build $(LDFLAGS) -o $(PAYLOAD_DIR)/mips64/reverse_tcp ./cmds/rshell
	GOOS=linux GOARCH=mips64 GOMIPS=softfloat $(GOFLAGS) $(GO) build $(LDFLAGS) -o $(PAYLOAD_DIR)/mips64/bind_tcp ./cmds/rshell

payloads-x86:
	GOOS=linux GOARCH=386 $(GOFLAGS) $(GO) build $(LDFLAGS) -o $(PAYLOAD_DIR)/x86/reverse_tcp ./cmds/rshell
	GOOS=linux GOARCH=386 $(GOFLAGS) $(GO) build $(LDFLAGS) -o $(PAYLOAD_DIR)/x86/bind_tcp ./cmds/rshell

payloads-x86_64:
	GOOS=linux GOARCH=amd64 $(GOFLAGS) $(GO) build $(LDFLAGS) -o $(PAYLOAD_DIR)/x86_64/reverse_tcp ./cmds/rshell
	GOOS=linux GOARCH=amd64 $(GOFLAGS) $(GO) build $(LDFLAGS) -o $(PAYLOAD_DIR)/x86_64/bind_tcp ./cmds/rshell

test:
	$(GOFLAGS) $(GO) test ./...

test-v:
	$(GOFLAGS) $(GO) test -v ./...

lint:
	$(GO) vet ./...

clean:
	rm -rf $(OUTPUT_DIR)/
	rm -f $(PAYLOAD_DIR)/arm/reverse_tcp $(PAYLOAD_DIR)/arm/bind_tcp
	rm -f $(PAYLOAD_DIR)/arm64/reverse_tcp $(PAYLOAD_DIR)/arm64/bind_tcp
	rm -f $(PAYLOAD_DIR)/mips/reverse_tcp $(PAYLOAD_DIR)/mips/bind_tcp
	rm -f $(PAYLOAD_DIR)/mipsle/reverse_tcp $(PAYLOAD_DIR)/mipsle/bind_tcp
	rm -f $(PAYLOAD_DIR)/mips64/reverse_tcp $(PAYLOAD_DIR)/mips64/bind_tcp
	rm -f $(PAYLOAD_DIR)/x86/reverse_tcp $(PAYLOAD_DIR)/x86/bind_tcp
	rm -f $(PAYLOAD_DIR)/x86_64/reverse_tcp $(PAYLOAD_DIR)/x86_64/bind_tcp
