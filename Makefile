ME=$(lastword $(MAKEFILE_LIST))
MENAME := ffcadcaed

SYSTEM_PYTHON := python3
VENV := .venv
PYTHON := $(VENV)/bin/python3

DOCKER := DOCKER_BUILDKIT=1 BUILDKIT_PROGRESS=plain docker

CERTS_DIR := _certs
KEYTABS_DIR := _krbbrb

SERVICE_NAME := SERVICE
CLIENT_NAME := CLIENT

SERVICE_HOST := localhost
SERVICE_PORT := 3443
SERVICE_URL := https://$(SERVICE_HOST):$(SERVICE_PORT)/hallo-there/

##
help:
	@echo "please, just go away"
	@echo ""
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(ME) | sed 's/:.\+## */ -- /'


##
tea: certs-create docker-build-all compose-up  ## make tea from container

##
venv:  ## virtualenv
	[ -f $(PYTHON) ] || \
	$(SYSTEM_PYTHON) -m venv $(VENV) --clear && \
	$(PYTHON) -m pip install -r requirements.txt

##
run-service:  ## run service
	$(PYTHON) -u service.py \
	--port $(SERVICE_PORT) \
	--cert $(CERTS_DIR)/service.crt --key $(CERTS_DIR)/service.key \
	--cacert $(CERTS_DIR)/root-ca.crt \
	--jwt-public-key $(CERTS_DIR)/jwt-public.key \
	--krb-keytab $(KEYTABS_DIR)/service.keytab --krb-principal $(SERVICE_NAME)

run-client-curl:  ## rrun curl client
	curl -i -s \
	$(SERVICE_URL) \
	--cert $(CERTS_DIR)/client.crt --key $(CERTS_DIR)/client.key \
	--cacert $(CERTS_DIR)/root-ca.crt \
	--header "X-API-KEY: $(CLIENT_NAME):$(CLIENT_NAME)" \
	--negotiate -u ":" --service-name $(SERVICE_NAME)

run-client: ## run client
	$(PYTHON) -u client.py -v -i \
	$(SERVICE_URL) \
	--cert $(CERTS_DIR)/client.crt --key $(CERTS_DIR)/client.key \
	--cacert $(CERTS_DIR)/root-ca.crt \
	--jwt-private-key $(CERTS_DIR)/jwt-private.key \
	--negotiate --service-name $(SERVICE_NAME)/$(SERVICE_HOST) --principal $(CLIENT_NAME)

kinit-init-client:
	-kdestroy
	-klist -k $(KEYTABS_DIR)/client.keytab
	-kinit -V CLIENT -k -t $(KEYTABS_DIR)/client.keytab
	-klist


##
compose-up:
	$(DOCKER) compose \
	--file dockers/service-client-kdc.yml \
	up \
	--force-recreate \
	--abort-on-container-exit


##
docker-build-all: docker-build-service-client docker-build-kdc

docker-build-service-client:
	$(DOCKER) build -t $(MENAME)-sc -f dockers/service-client.dockerfile .

docker-build-kdc:
	$(DOCKER) build -t $(MENAME)-kdc -f dockers/kdc.dockerfile .

docker-run-kdc:
	$(DOCKER) run -it --rm --name $(MENAME)-kdc $(MENAME)-kdc

docker-run-service-client-shell:
	$(DOCKER) run -it --rm --name $(MENAME) $(MENAME)-sc /bin/bash

docker-run-service-client-service:
	$(DOCKER) run -it --rm \
	--publish 3443:3443 \
	--volume $(PWD)/_krbbrb:/app/_krbbrb \
	--name $(MENAME)-service \
	$(MENAME)-sc \
	make run-service

docker-run-service-client-client:
	$(DOCKER) run -it --rm \
	--volume $(PWD)/_krbbrb:/app/_krbbrb \
	--name $(MENAME)-client \
	$(MENAME)-sc \
	make run-client

##
certs-create:  ## create self-signed certs

	mkdir -vp $(CERTS_DIR)

	# (1) root CA
	openssl genpkey -algorithm RSA -out "$(CERTS_DIR)/root-ca.key"
	openssl req -x509 -new -nodes -sha256 -days 9999 \
	-addext "keyUsage=critical,digitalSignature,keyCertSign" \
	-subj "/O=DEV.LOCAL/CN=root ca" \
	-key "$(CERTS_DIR)/root-ca.key" \
	-out "$(CERTS_DIR)/root-ca.crt"

	# (2) service (CN=localhost, ALT=service.dev.local)
	openssl genpkey -algorithm RSA -out "$(CERTS_DIR)/service.key"
	echo "subjectAltName=DNS:service,DNS:service.dev.local,DNS:localhost" > "$(CERTS_DIR)/service.ext"
	openssl req -new \
	-subj "/O=DEV.LOCAL/CN=localhost" \
	-key "$(CERTS_DIR)/service.key" \
	-out "$(CERTS_DIR)/service.csr"
	openssl x509 -req -days 999 -sha256 \
	-CA "$(CERTS_DIR)/root-ca.crt" -CAkey "$(CERTS_DIR)/root-ca.key" -CAcreateserial \
	-in "$(CERTS_DIR)/service.csr" -extfile "$(CERTS_DIR)/service.ext" \
	-out "$(CERTS_DIR)/service.crt"

	# (3) client
	openssl genpkey -algorithm RSA -out "$(CERTS_DIR)/client.key"
	openssl req -new \
	-subj "/O=DEV.LOCAL/CN=client-$(shell date +'%M%S')" \
	-key "$(CERTS_DIR)/client.key" \
	-out "$(CERTS_DIR)/client.csr"
	openssl x509 -req -days 999 -sha256 \
	-CA "$(CERTS_DIR)/root-ca.crt" -CAkey "$(CERTS_DIR)/root-ca.key" -CAcreateserial \
	-in "$(CERTS_DIR)/client.csr" \
	-out "$(CERTS_DIR)/client.crt" \

	#
	openssl x509 -in "$(CERTS_DIR)/root-ca.crt" -text -noout | grep -E "CN=|DNS:" | sed 's/ \+/ > /'
	openssl x509 -in "$(CERTS_DIR)/service.crt" -text -noout | grep -E "CN=|DNS:" | sed 's/ \+/ > /'
	openssl x509 -in "$(CERTS_DIR)/client.crt" -text -noout | grep -E "CN=|DNS:" | sed 's/ \+/ > /'

	# jwt rsa keys
	openssl genpkey -algorithm RSA -out "$(CERTS_DIR)/jwt-private.key"
	openssl rsa -pubout -in "$(CERTS_DIR)/jwt-private.key" -out "$(CERTS_DIR)/jwt-public.key"


##
dev-venv:  venv
	$(PYTHON) -m pip install black isort flake8 flake8-bugbear flake8-comprehensions

dev-autoformat:
	$(PYTHON) -m isort --profile black service.py client.py
	$(PYTHON) -m black --line-length 110 service.py client.py

dev-lint:
	$(PYTHON) -m black --line-length 110 --check service.py client.py
	$(PYTHON) -m flake8 --max-line-length 110 -v service.py client.py

