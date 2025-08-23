#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "peer.h"
#include "btc.h"
#include "cJSON.h"
#include "netutils.h"

int main(int argc, char **argv)
{
	char *pa = argv[1];
	int pp = atoi(argv[2]);
	int sockfd, status;
	
	if (argc < 3)
	{
		printf("USAGE: %s host port\n", argv[0]);
		exit(1);
	}

	printf("Bitcoin peer discovery poc\n"
		"using peer \"%s\" as the root peer\n", pa);

	sockfd = tcp_socket_connect(pa, pp);

	blob_t *btc_msg_version_payload = btc_create_version_payload();
	blob_t *btc_msg_version = btc_create_msg("version",
			btc_msg_version_payload->data, btc_msg_version_payload->len);
	blob_t *btc_msg_verack = btc_create_msg("verack", NULL, 0);
	blob_t *btc_msg_getaddr = btc_create_msg("getaddr", NULL, 0);
	

	uint8_t buf[32768];
	size_t buf_len = sizeof(buf);
	size_t offset = 0;
	int keep_reading = 1;

	write_blob(sockfd, btc_msg_version);

	peer_t *peers = NULL;

	while (keep_reading)
	{
		ssize_t n = sock_read(sockfd, buf + offset, buf_len - offset);
		if (n == 0)
		{
			puts("read: eof");
			break;
		}
		else if (n == -1)
		{
			perror("read");
			break;
		}

		offset += n;
		size_t pos = 0;
		while (offset - pos >= BTC_HDR_SIZE)
		{
			uint32_t payload_len = *(uint32_t *)(buf + pos + BTC_HDR_OFFSET_PAYLOAD_SIZE);
			if (offset - pos < payload_len + BTC_HDR_SIZE)
			{
				break;
			}

			uint8_t *cmd = buf + pos + BTC_HDR_OFFSET_CMD;
			uint8_t *p = buf + pos + BTC_HDR_SIZE;

			blob_t blob;
			blob.data = buf + pos;
			blob.len = payload_len + BTC_HDR_SIZE;
			blob_hexdump(&blob, 0);
	
			if(!strncmp(cmd, "version", BTC_HDR_CMD_SIZE))
			{
				write_blob(sockfd, btc_msg_verack);
			}
			else if(!strncmp(cmd, "verack", BTC_HDR_CMD_SIZE))
			{
				write_blob(sockfd, btc_msg_getaddr);
			}
			else if(!strncmp(cmd, "addr", BTC_HDR_CMD_SIZE))
			{
				btc_parse_addr(&blob, &peers);
				keep_reading = 0;
			}
			else if(!strncmp(cmd, "addrv2", BTC_HDR_CMD_SIZE))
			{
				puts("received addrv2");
			}
			else
			{
				puts("received unknown msg");
			}

			pos += payload_len + 24;
		}

		if (pos > 0)
		{
			memmove(buf, buf + pos, offset - pos);
			offset -= pos;
		}
	}

	if (peers)
	{
		dump_peers_tree(peers);
	}
	else
	{
		puts("no peers found");
	}

	sock_close(sockfd);
	puts("disconnected");
	
	return 0;
}
