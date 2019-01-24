ARCH=$(shell go env GOARCH)
VERSION := $(shell egrep -o 'const Version = "[0-9]+\.[0-9]+\.[0-9]+"' main.go | egrep -o '[0-9]+\.[0-9]+\.[0-9]+')
BINARY_NAME=hibp-cli
BUILD_FILES=main.go hibpclient.go hibputils.go
BUILD_CMD=go build $(BUILD_FILES)

build:
	rm -rf "dist/*"
	mkdir -p dist/

	GOOS=darwin $(BUILD_CMD)
	bzip2 -c $(BINARY_NAME) > dist/$(BINARY_NAME)-$(VERSION)-darwin-$(ARCH).bz2

	GOOS=linux $(BUILD_CMD)
	bzip2 -c $(BINARY_NAME) > dist/$(BINARY_NAME)-$(VERSION)-linux-$(ARCH).bz2

	GOOS=windows $(BUILD_CMD)
	bzip2 -c $(BINARY_NAME).exe > dist/$(BINARY_NAME)-$(VERSION)-windows-$(ARCH).exe.bz2

test:
	go test -v

release: test build

all:
	$(error please pick a target)
