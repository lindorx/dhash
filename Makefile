CC = gcc

.SUFFIXES: .c .o
.PHONY: build install uninstall test clean

BASE_PATH_INCLUDE = /usr/include/dhash
BASE_PATH_LIB = /usr/lib/x86_64-linux-gnu
DHASH_PATH = dhash-install
DHASH_PATH_INCLUDE = $(DHASH_PATH)$(BASE_PATH_INCLUDE)
DHASH_PATH_LIB = $(DHASH_PATH)$(BASE_PATH_LIB)
DHASH_SO = libdhash.so
SRC = src
INCLUDE = include
ALL_SRCS = $(wildcard $(SRC)/*.c) $(wildcard $(SRC)/**/*.c)
DEP = $(patsubst %c, %d, $(ALL_SRCS))
OBJS = $(ALL_SRCS:.c=.o)

CFLAGS = -I $(INCLUDE)

build: $(DHASH_SO)
$(DHASH_SO): $(OBJS)
	echo $(ALL_SRCS)
	mkdir -p $(DHASH_PATH_INCLUDE) $(DHASH_PATH_LIB)
	cp $(INCLUDE)/* $(DHASH_PATH_INCLUDE)
	$(CC) $(CFLAGS) -shared -o $(DHASH_SO) $(OBJS) 

$(DEP): %.d: %.c
	$(CC) $(CFLAGS) -MM $< > $@

-include $(DEP)

.c.o:
	$(CC) $(CFLAGS) -Wall -g -fPIC -o $(@) -c $<

install: $(DHASH_SO)
	mkdir -p $(BASE_PATH_INCLUDE)
	cp $(DHASH_SO) $(BASE_PATH_LIB)
	CP $(INCLUDE)/* $(BASE_PATH_INCLUDE)

uninstall:
	rm $(BASE_PATH_LIB)/$(DHASH_SO) $(BASE_PATH_INCLUDE)

TEST_BIN = test/test.out
test: $(TEST_BIN)
$(TEST_BIN): test/main.c $(DHASH_SO)
	$(CC) $(CFLAGS) $^ $(DHASH_SO) -o $(TEST_BIN)

clean:
	rm -rf test/*.out $(DHASH_PATH_INCLUDE) $(DHASH_PATH_LIB) $(DHASH_SO) $(OBJS) $(DEP)
