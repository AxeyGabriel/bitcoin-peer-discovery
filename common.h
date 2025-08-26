#ifndef __MAIN_H__

#include <inttypes.h>
#include <stddef.h>

#define PEERS_IPV4_ONLY
#define DEBUG_DUMP_COMM
#undef DEBUG_DUMP_COMM

#define SERIALIZE_LE(val, buf) 									\
	do {														\
		for (size_t i = 0; i < sizeof((val)); i++) {			\
			((uint8_t *)(buf))[i] = ((val) >> (8*i)) & 0xFF;	\
		}														\
	} while(0)
#define __MAIN_H__

typedef struct
{
	uint8_t *data;
	size_t len;
} blob_t;

void blob_hexdump(blob_t *b, int tx);
int write_blob(int sockfd, blob_t *b);

#endif
