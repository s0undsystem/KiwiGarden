.PHONY: all ui build test fuzz run clean

all: build

ui:
	cd web && npm ci --no-audit --no-fund && npm run build

build: ui
	go build -o kiwi-garden ./cmd/kiwi-garden

test:
	go vet ./...
	go test ./...

fuzz:
	go test ./internal/kiwiws -run=^$$ -fuzz=FuzzReadFrame -fuzztime=20s
	go test ./internal/kiwi -run=^$$ -fuzz=FuzzParseSND -fuzztime=20s
	go test ./internal/kiwi -run=^$$ -fuzz=FuzzADPCM -fuzztime=10s
	go test ./internal/kiwi -run=^$$ -fuzz=FuzzParseMSG -fuzztime=10s
	go test ./internal/directory -run=^$$ -fuzz=FuzzParse -fuzztime=20s
	go test ./internal/sanitize -run=^$$ -fuzz=FuzzText -fuzztime=10s

run: build
	./kiwi-garden

clean:
	rm -rf kiwi-garden internal/ui/dist/* web/node_modules
	touch internal/ui/dist/.keep
