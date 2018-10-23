CC=gcc
CFLAGS=-fno-builtin-memset -Wall -lm
RM=rm -f
SRC=memzero_bench.c
OUT=memzero_bench

all: build

build: $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(OUT)

debug: CFLAGS+= -DDEBUG
debug: build

.PHONY: clean

clean:
	$(RM) $(OUT)