DOCKER_IMAGE=golang:1.8.3
DOCKER_RUN=docker run --rm -v "$(CURDIR)":/v -w /v $(DOCKER_IMAGE)

clean:
	$(DOCKER_RUN) make $@

build:
	$(DOCKER_RUN) make $@

build/goflyway:
	$(DOCKER_RUN) make $@
