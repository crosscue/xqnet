.PHONY: build test vet race check clean

build:
	mkdir -p bin
	CGO_ENABLED=1 go build -o bin/xqnet ./cmd/xqnet

test:
	go test ./...

vet:
	go vet ./...

race:
	go test -race ./...

check: test vet race

clean:
	rm -rf bin
