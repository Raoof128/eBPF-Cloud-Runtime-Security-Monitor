.PHONY: all bpf agent dashboard test fmt lint e2e clean

BPF_OBJ := ebpf/process_monitor.bpf.o
AGENT   := bin/ecrsm-agent
# <asm/types.h> lives in the architecture's include directory on Debian and Ubuntu.
ARCH_INCLUDE := /usr/include/$(shell uname -m)-linux-gnu

all: bpf agent

# Needs clang and the libbpf headers (Debian/Ubuntu: clang libbpf-dev).
bpf:
	clang -O2 -g -Wall -target bpf -I$(ARCH_INCLUDE) -c ebpf/process_monitor.c -o $(BPF_OBJ)

agent:
	cd agent && go build -o ../$(AGENT) .

dashboard:
	cd dashboard && npm ci && npm run build

test:
	cd agent && go vet ./... && go test -race ./...

fmt:
	gofmt -w agent/*.go

lint:
	test -z "$$(gofmt -l agent)"
	cd dashboard && npm run lint

# Loads the probes into the running kernel, so it needs Linux and root (it calls sudo).
e2e:
	bash scripts/e2e_smoke.sh

clean:
	rm -rf $(BPF_OBJ) bin
