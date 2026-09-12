CONTAINER_TOOL ?= docker

.PHONY: generate-certs up down restart clean status

generate-certs:
	./generate-certs.sh

up: generate-certs
	$(CONTAINER_TOOL) compose up -d

down:
	$(CONTAINER_TOOL) compose down

restart: down up

clean: down
	rm -rf certs data

status:
	$(CONTAINER_TOOL) compose ps