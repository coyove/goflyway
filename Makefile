IMAGE_NAME?=coyove/goflyway

.PHONY: clean
clean:
	$(RM) -r build

build: build/goflyway

build/goflyway:
	mkdir -p build
	go build -o $@ main.go

.PHONY: build_image
build_image:
	docker build -t $(IMAGE_NAME) .
