.PHONY: build run clean docker docker-up docker-down docker-build docker-logs test

GOPROXY_FLAGS := GOPROXY=https://goproxy.cn,direct

build:
	$(GOPROXY_FLAGS) go build -ldflags="-s -w" -o alterhive .

run: build
	./alterhive

clean:
	rm -f alterhive

test:
	$(GOPROXY_FLAGS) go test ./...

docker-build:
	docker compose build

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

docker:
	docker compose build
