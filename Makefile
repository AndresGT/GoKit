.PHONY: build test test-race cover tidy vet fmt

# GoKit - comandos de desarrollo
PACKAGES ?= ./...

build:
	go build $(PACKAGES)

test:
	go test -count=1 $(PACKAGES)

test-race:
	go test -race -count=1 $(PACKAGES)

cover:
	go test -covermode=atomic -coverprofile=coverage.out $(PACKAGES)
	go tool cover -func=coverage.out

tidy:
	go mod tidy

vet:
	go vet $(PACKAGES)

fmt:
	gofmt -l -w .
