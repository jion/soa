TARGETS=../obj/client ../obj/server

# Opciones del compilador
CC=gcc
CCOPTS=-Wall -Wextra

# Directorios definidos
#SRCDIR   = src
#OBJDIR   = obj

.PHONY: all clean

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

../obj/%: %.c
	$(CC) $(CCOPTS) -o $@ $<
