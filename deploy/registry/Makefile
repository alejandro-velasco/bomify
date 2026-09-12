CONTAINER_TOOL ?= docker

.PHONY: generate-certs generate-htpasswd up down restart clean status

generate-certs:
	./generate-certs.sh

generate-htpasswd:
	./generate-htpasswd.sh

up: generate-certs generate-htpasswd
	$(CONTAINER_TOOL) compose up -d

down:
	$(CONTAINER_TOOL) compose down

restart: down up

clean: down
	rm -rf certs data auth

status:
	$(CONTAINER_TOOL) compose ps