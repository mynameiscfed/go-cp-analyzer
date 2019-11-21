.PHONY: all clean
all:
	go vet .
	go fmt .
	go test .
	go build
clean:
	@rm go-cp-analyzer