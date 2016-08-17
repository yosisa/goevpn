SOURCES := $(shell find . -name '*.go')
LDFLAGS := "-s"
BIN := goevpn

build: $(BIN)

$(BIN): $(SOURCES)
	go build -ldflags $(LDFLAGS)

clean:
	-rm $(BIN)

.PHONY: build clean
