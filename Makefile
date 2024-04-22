CFLAGS += -O2 -Wall -Wextra
PREFIX = /usr

.PHONY: all install clean

all: enter

weakbox.o: weakbox.c arg.h
	$(CC) -c $< -o $@ $(CFLAGS) $(CPPFLAGS)

weakbox: weakbox.o
	$(CC) $< -o $@ $(LDFLAGS)

install: weakbox weakbox.1
	cp weakbox $(PREFIX)/bin/
	cp weakbox.1 $(PREFIX)/share/man/man1/

clean:
	rm -f weakbox weakbox.1