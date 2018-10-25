CC=gcc
CFLAGS=-Wall
LIBS=-lm
RM=rm -rf

SRC_DIR=src
SRC=$(SRC_DIR)/memzero_bench.c
OUT_DIR=build
OUT=$(OUT_DIR)/memzero_bench

all: build

build: $(SRC)
	mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) $(SRC) $(LIBS) -o $(OUT)

debug: CFLAGS+= -DDEBUG
debug: build

.PHONY: clean

clean:
	$(RM) $(OUT_DIR)