DEBUG ?= 0

ifeq ($(DEBUG),1)
    CFLAGS = -Og -g -DDEBUG
    LDFLAGS = -lssl -lcrypto
else
    CFLAGS = -I/usr/include -O3 -flto -march=native -funroll-loops -fomit-frame-pointer -fstrict-aliasing
    LDFLAGS = -lssl -lcrypto -flto
endif

CFLAGS += -Wall -Wextra -Wshadow -Wcast-align -I/usr/include

SRC = main.c blob.c btc.c peer.c netutils.c
OBJ = $(SRC:.c=.o)
CC = gcc
TARGET = main

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ)
