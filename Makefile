ARCH=$(shell go env GOARCH)
VERSION := $(shell egrep -o 'const Version = "v[0-9]+\.[0-9]+\.[0-9]+"' main.go | egrep -o 'v[0-9]+\.[0-9]+\.[0-9]+')
BINARY_NAME=hibp-cli
BUILD_FILES=main.go hibpclient.go hibputils.go

build:
	rm -rf dist/*
	mkdir -p dist/

	GOOS=linux go build -o dist/$(BINARY_NAME)-$(VERSION)-linux-$(ARCH) $(BUILD_FILES)
	GOOS=darwin go build -o dist/$(BINARY_NAME)-$(VERSION)-darwin-$(ARCH) $(BUILD_FILES)
	GOOS=windows go build -o dist/$(BINARY_NAME)-$(VERSION)-windows-$(ARCH).exe $(BUILD_FILES)

	find dist/ -name "$(BINARY_NAME)-*" -exec bzip2 {} \;

test:
	go test -v

release: test build

all:
	$(error please pick a target)
