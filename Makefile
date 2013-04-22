TARGETS=client server

CC=gcc
CCOPTS=-Wall -Wextra

.PHONY: all clean

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

%: %.c
	$(CC) $(CCOPTS) -o $@ $<
