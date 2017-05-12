CFLAGS=-Wall
LIBS=-lcrypto -lpthread -lm -lcurl
CC=gcc

all: bt_client bt_lib bt_encode
	$(CC) bencode/bencode.o bt_lib.o bt_client.o -o btfs $(LIBS)

bt_client: bt_client.c
	$(CC) $(CFLAGS) -c bt_client.c -o bt_client.o

bt_lib: bt_lib.c bt_lib.h
	$(CC) $(CFLAGS) -c bt_lib.c -o bt_lib.o 

bt_encode:
	make -C bencode bencode.o

clean:
	rm -rf *.o btfs && make -f bencode/Makefile clean
