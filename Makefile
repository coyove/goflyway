IMAGE_NAME?=coyove/goflyway
NAME?=goflyway
SOURCE?=main.go
LIST?=chinalist.txt

.PHONY: release windows darwin linux clean

clean:
	$(RM) -r build

build: build/goflyway

build/goflyway:
	mkdir -p build && go build -o $@ main.go && cp $(LIST) build/

.PHONY: build_image
build_image:
	docker build -t $(IMAGE_NAME) .

release: windows darwin linux

release = GOOS=$(1) GOARCH=$(2) go build -o build/$(3) && cp $(LIST) build/
tar = cd build && tar -cvzf $(NAME)_$(1)_$(2).tar.gz $(NAME) $(LIST) && rm $(NAME)
zip = cd build && zip $(NAME)_$(1)_$(2).zip $(NAME).exe $(LIST) && rm $(NAME).exe

linux: release/linux_386 release/linux_amd64

release/linux_386: $(SOURCE)
	$(call release,linux,386,$(NAME))
	$(call tar,linux,386)

release/linux_amd64: $(SOURCE)
	$(call release,linux,amd64,$(NAME))
	$(call tar,linux,amd64)

darwin: release/darwin_amd64

release/darwin_amd64: $(SOURCE)
	$(call release,darwin,amd64,$(NAME))
	$(call tar,darwin,amd64)

windows: release/windows_386 release/windows_amd64

release/windows_386: $(SOURCE)
	$(call release,windows,386,$(NAME).exe)
	$(call zip,windows,386)

release/windows_amd64: $(SOURCE)
	$(call release,windows,amd64,$(NAME).exe)
	$(call zip,windows,amd64)