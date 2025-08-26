#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include "common.h"

void blob_hexdump(blob_t *b, int tx)
{
	uint8_t *data = b->data;
	size_t len = b->len;

	for (size_t i = 0; i < len; i += 16)
	{
		printf("%s %08zx  ", tx ? "<" : ">>", i);
		for (size_t j = 0; j < 16; j++)
		{
			if (i + j < len)
			{
				printf("%02X ", data[i + j]);
			}
			else
			{
				printf("   ");
			}
		}

		printf(" ");

		for (size_t j = 0; j < 16 && i + j < len; j++)
		{
			uint8_t c = data[i + j];
			printf("%c", (c >= 32 && c <= 126) ? c : '.');
		}

		puts("");
	}
}

int write_blob(int sockfd, blob_t *b)
{
#ifdef DEBUG_DUMP_COMM
	blob_hexdump(b, 1);
#endif
	int ret = write(sockfd, b->data, b->len);
	//printf("sent %d bytes\n", b->len);
	return ret;
}
