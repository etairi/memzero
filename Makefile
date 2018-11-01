CC=gcc
CFLAGS=-Wall -O3
LIBS=-lm
RM=rm -rf

SRC=src/memzero.c src/memzero_test.c
OUT_DIR=build
OUT=$(OUT_DIR)/memzero_test

all: build

build: $(SRC)
	mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) $(SRC) $(LIBS) -o $(OUT)

debug: CFLAGS+= -DDEBUG
debug: build

.PHONY: clean

clean:
	$(RM) $(OUT_DIR)