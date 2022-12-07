BINARY_NAME=wrapernmap

build:
	go build -o ${BINARY_NAME} cmd/main.go


run:
	./${BINARY_NAME}

build_and_run: build run

clean:
	go clean
	rm ${BINARY_NAME}

lint:
	golangci-lint run

tests:
	go test

