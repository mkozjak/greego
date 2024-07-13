.DEFAULT_GOAL := build
BINARY_NAME=greego

build:
	go build \
		-ldflags "-X main.appVersion=$$(git rev-parse --short HEAD)" \
		-o /tmp/${BINARY_NAME} cmd/greego.go

run: build
	/tmp/${BINARY_NAME}

install: build
	cp /tmp/${BINARY_NAME} $$GOPATH/bin/greego

clean:
	go clean
	rm /tmp/${BINARY_NAME}
