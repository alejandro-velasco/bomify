BINARY := bin/bomify

.PHONY: build test run tidy clean

build:
	go build -o $(BINARY) .

test:
	go test ./...

run: build
	./$(BINARY)

tidy:
	go mod tidy

clean:
	rm -rf bin dist
