BINARY_NAME=wrapernmap

build:
	go build -o ${BINARY_NAME} cmd/main.go


run:
	./${BINARY_NAME}

build_and_run: build run

run2:
	go run cmd/main.go

clean:
	go clean
	rm ${BINARY_NAME}

lint:
	golangci-lint run

tests:
	go test

