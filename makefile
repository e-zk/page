.POSIX:
.SUFFIXES:
.PHONY: clean

PREFIX = /usr/local

page: main.go
	go build -ldflags "-w -s" -o page -v main.go

install: page
	install -c -s -m 0755 page $(PREFIX)/bin

clean:
	rm -f page
	go clean
