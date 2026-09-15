BIN    := bin
WORKER := $(BIN)/scanner-worker
DAEMON := $(BIN)/edr-daemon
CTL    := $(BIN)/edr-ctl

.PHONY: all build clean run-daemon test-eicar

all: build

build:
	@mkdir -p $(BIN)
	go build -o $(WORKER) ./cmd/scanner-worker
	go build -o $(DAEMON) ./cmd/edr-daemon
	go build -o $(CTL)    ./cmd/edr-ctl

clean:
	rm -rf $(BIN)

# Run the daemon against a local socket and the just-built worker.
run-daemon: build
	@mkdir -p /tmp/edr
	$(DAEMON) -socket /tmp/edr/control.sock -worker $(PWD)/$(WORKER)

# In a second terminal: make test-eicar
test-eicar:
	@mkdir -p /tmp/edr
	@printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$$H+H*' > /tmp/edr/eicar.txt
	@printf 'benign content\n' > /tmp/edr/clean.txt
	@echo "--- clean file ---"
	@$(CTL) -socket /tmp/edr/control.sock scan /tmp/edr/clean.txt || true
	@echo "--- eicar file ---"
	@$(CTL) -socket /tmp/edr/control.sock scan /tmp/edr/eicar.txt || true