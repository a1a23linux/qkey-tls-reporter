GO ?= go
PYTHON ?= python3

.PHONY: build check test interop demo clean

build:
	$(GO) build -trimpath -o bin/qkey-tls-reporter ./cmd/qkey-tls-reporter

test:
	$(GO) test -race -count=1 ./...

interop:
	$(GO) test -tags=interop -race -count=1 -run OpenSSL -v ./internal/probe

check:
	@test -z "$$($(GO)fmt -l cmd internal)" || { echo 'Run gofmt on cmd/ and internal/'; exit 1; }
	$(GO) vet ./...
	$(GO) test -race -count=1 ./...
	$(PYTHON) scripts/check_release.py
	$(PYTHON) -m unittest discover -s scripts -p 'test_*.py' -v

demo: build
	./bin/qkey-tls-reporter -demo -out results/demo

clean:
	rm -rf bin
