CONTAINER_TOOL ?= docker

.PHONY: generate-certs up down clean

generate-certs:
	./generate-certs.sh

up: generate-certs
	$(CONTAINER_TOOL) compose up -d

down:
	$(CONTAINER_TOOL) compose down

clean: down
	rm -rf certs data

status:
	$(CONTAINER_TOOL) compose ps