ifneq (,$(wildcard ./.env))
    include .env
    export
endif

.PHONY: proto run dev build test tidy migrate-status migrate-up migrate-down \
		migrate-create docker-up docker-down

PROTO_SRC := proto
PROTO_DEPS := third_party
GEN_OUT := gen

# Proto Generation
proto:
	@echo "==> Generating auth protos..."
	protoc \
		-I $(PROTO_SRC) \
		-I $(PROTO_DEPS) \
		--go_out=$(GEN_OUT) --go_opt=paths=source_relative \
		--go-grpc_out=$(GEN_OUT) --go-grpc_opt=paths=source_relative \
		--grpc-gateway_out=$(GEN_OUT) --grpc-gateway_opt=paths=source_relative \
		$(PROTO_SRC)/auth/v1/auth.proto
	
	protoc \
		-I $(PROTO_SRC) \
		-I $(PROTO_DEPS) \
		--go_out=$(GEN_OUT) --go_opt=paths=source_relative \
		--go-grpc_out=$(GEN_OUT) --go-grpc_opt=paths=source_relative \
		$(PROTO_SRC)/auth/v1/errors.proto
	@echo "==> Proto generation complete."

# Application
run:
	go run ./cmd/server

dev:
	air

build:
	go build -o bin/core-auth ./cmd/server

test:
	go test ./... -v

tidy:
	go mod tidy

# Port Cleanup
clean-port:
	@echo "==> Cleaning up port 50051..."
	@lsof -t -i :50051 | xargs kill -9 || echo "No process found on port 50051."

# Database
migrate-status:
	goose -dir migrations postgres "$(DATABASE_URL)" status

migrate-up:
	goose -dir migrations postgres "$(DATABASE_URL)" up

migrate-down:
	goose -dir migrations postgres "$(DATABASE_URL)" down

migrate-create:
	@read -p "Migration name: " name; \
	goose -dir migrations create $$name sql

db-shell:
	docker exec -it core-auth-postgres psql -U core_auth -d core_auth

redis-shell:
	docker exec -it core-auth-redis redis-cli

# docker
docker-up:
	docker compose up -d

docker-down:
	docker compose down