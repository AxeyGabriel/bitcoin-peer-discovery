CC = gcc
CFLAGS = -I/usr/include -Og
LDFLAGS = -lssl -lcrypto
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
