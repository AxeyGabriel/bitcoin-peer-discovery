CC = gcc
#CFLAGS = -I/usr/include -Og -g
CFLAGS = -I/usr/include -O3 -flto -march=native -funroll-loops -fomit-frame-pointer -fstrict-aliasing 
CFLAGS += -Wall -Wextra -Wshadow -Wcast-align
LDFLAGS = -lssl -lcrypto -flto
TARGET = main
SRC = main.c blob.c btc.c peer.c netutils.c
OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ)
