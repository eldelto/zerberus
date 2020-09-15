build: generate
	@echo Building cmd/zerberus-server/main.go
	@go build -o bin/zerberus-server cmd/zerberus-server/main.go

download:
	@echo Download go.mod dependencies
	@go mod download

install-tools: download
	@echo Installing tools from tools.go
	@cat tools.go | grep _ | awk -F'"' '{print $$2}' | xargs -tI % go install %

generate:
	@echo Generating source files
	@swagger generate server -f api/swagger.yml
run:
	@echo Starting Zerberus
	@go run cmd/zerberus-server/main.go --port 8080

test:
	@echo Testing Zerberus
	@go test ./...
