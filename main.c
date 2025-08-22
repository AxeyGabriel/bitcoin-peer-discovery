#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>
#include <openssl/sha.h>
#include "cJSON.h"

#define SERIALIZE_LE(val, buf) 									\
	do {														\
		for (size_t i = 0; i < sizeof(val); i++) {				\
			((uint8_t *)(buf))[i] = ((val) >> (8*i)) & 0xFF;	\
		}														\
	} while(0)

#define BTC_HDR_OFFSET_MAGIC		0
#define BTC_HDR_OFFSET_CMD			4
#define BTC_HDR_OFFSET_PAYLOAD_SIZE	16
#define BTC_HDR_OFFSET_CHECKSUM		20
#define BTC_HDR_SIZE				24
#define BTC_HDR_CMD_SIZE			12

#define BTC_VER_OFFSET_TIME 		12
#define BTC_VER_OFFSET_ADDR_RECV 	20

typedef struct
{
	uint8_t *data;
	size_t len;
} blob_t;

void blob_hexdump(blob_t *b, int tx) {
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

/*
 * Calculates the double SHA256 checksum
 * output: out[0..3] containing the 4 bytes of the checksum
 */
void btc_calculate_checksum(uint8_t *payload, size_t len, uint8_t *out)
{
	uint8_t hash[32][2];
	SHA256(payload, len, hash[0]);
	SHA256(hash[0], 32, hash[1]);
	memcpy(out, hash[1], 4);
}

blob_t *btc_create_version_payload(char *ip)
{
	static const uint8_t btc_msg_version_payload[] = {
		0x7f, 0x11, 0x01, 0x00, 					//version (4 bytes, little-endian) = 70015
		0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	// services (8 bytes) = 0
		0xc0,0x9a,0x5b,0x5f,0x00,0x00,0x00,0x00,	// timestamp (8 bytes) = 0x5F5B9AC0 (example)
		0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	// addr_recv: services (8 bytes) = 0
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	// addr_recv: IPv6/IPv4 placeholder (16 bytes) all zeros
		0x20,0x20,									// addr_recv: port (2 bytes) = 8333
		0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	// addr_from: services (8 bytes) = 0
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	// addr_from: IPv6/IPv4 placeholder (16 bytes) all zeros
		0x20,0x20,									// addr_from: port (2 bytes) = 8333
		0x2a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	// nonce (8 bytes) = 42
		0x00,
		0x00,0x00,0x00,0x00,
		0x01,
	};
	static const size_t btc_msg_version_payload_len = sizeof(btc_msg_version_payload);
	
	uint8_t *data = malloc(btc_msg_version_payload_len);
	blob_t *blob = malloc(sizeof(blob));
	blob->data = data;
	blob->len = btc_msg_version_payload_len;

	memcpy(blob->data, btc_msg_version_payload, blob->len);

	SERIALIZE_LE(time(NULL), blob->data + BTC_VER_OFFSET_TIME);
	inet_pton(AF_INET, ip, blob->data + BTC_VER_OFFSET_ADDR_RECV);

	return blob;
}

/*
 * Creates a binary blob containing the command
 * and the payload, already checksummed and ready
 * to be sent
 */
blob_t *btc_create_msg(const char *cmd, uint8_t *payload, size_t len)
{
	const uint32_t hdr_magic = 0xD9B4BEF9;
	const int hdr_size = 24;
	char *empty_str = "";
	size_t offset = 0;
	uint8_t header[hdr_size];
	blob_t *blob = malloc(sizeof(blob));
	blob->len = hdr_size + len;
	blob->data = malloc(blob->len);
	memset(blob->data, 0, blob->len);
	SERIALIZE_LE(hdr_magic, blob->data + offset);
	offset += 4;
	strncpy(blob->data + offset, cmd, strlen(cmd));
	offset += 12;
	SERIALIZE_LE((uint32_t)len, blob->data + offset);
	offset += 4;

	if (payload)
	{
		btc_calculate_checksum(payload, len, blob->data + offset);
		memcpy(blob->data + offset, payload, len);
	}
	else
	{
		btc_calculate_checksum(empty_str, 0, blob->data + offset);
	}

	return blob;
}

int write_blob(int sockfd, blob_t *b)
{
	blob_hexdump(b, 1);
	int ret = write(sockfd, b->data, b->len);
	//printf("sent %d bytes\n", b->len);
	return ret;
}


int tcp_socket_connect(char *host, int port, char *resolved_ip)
{
	int sockfd;
	struct sockaddr_in sa;
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	
	int status = getaddrinfo(host, NULL, &hints, &res);
	if (status != 0)
	{
		printf("error while resolving hostname: %s\n", gai_strerror(status));
		exit(1);
	}

	for (struct addrinfo *p = res; p != NULL; p = p->ai_next)
	{
		char ipstr[INET6_ADDRSTRLEN];
		void *addr;
		if (p->ai_family == AF_INET)
		{
			struct sockaddr_in *addr4 = (struct sockaddr_in *)p->ai_addr;
			addr4->sin_port = htons(port);
			addr = &addr4->sin_addr;
		}
		else
		{
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)p->ai_addr;
			addr6->sin6_port = htons(port);
			addr = &addr6->sin6_addr;
		}
		
		inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
		printf("connecting to %s:%d ...\n", ipstr, port);
		strcpy(resolved_ip, ipstr);

		sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sockfd == -1) continue;

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
		{
			perror("failed to connect");
			close(sockfd);
			continue;
		}

		printf("connected\n");
		freeaddrinfo(res);
		return sockfd;
	}

	printf("all options failed. exiting\n");
	freeaddrinfo(res);
	exit(1);
}

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

	char resolved_ip[INET6_ADDRSTRLEN];
	sockfd = tcp_socket_connect(pa, pp, resolved_ip);

	blob_t *btc_msg_version_payload = btc_create_version_payload(resolved_ip);
	blob_t *btc_msg_version = btc_create_msg("version",
			btc_msg_version_payload->data, btc_msg_version_payload->len);
	blob_t *btc_msg_verack = btc_create_msg("verack", NULL, 0);
	blob_t *btc_msg_getaddr = btc_create_msg("getaddr", NULL, 0);
	

	uint8_t buf[8192];
	size_t buf_len = sizeof(buf);
	size_t offset = 0;

	write_blob(sockfd, btc_msg_version);

	while (1)
	{
		ssize_t n = read(sockfd, buf + offset, buf_len - offset);
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
				puts("received addr");
			}
			else if(!strncmp(cmd, "addrv2", BTC_HDR_CMD_SIZE))
			{
				puts("received addrv2");
			}
			else if(!strncmp(cmd, "ping", BTC_HDR_CMD_SIZE))
			{
				blob_t *btc_msg_pong = btc_create_msg("pong", p, payload_len);
				write_blob(sockfd, btc_msg_pong);
				free(btc_msg_pong->data);
				free(btc_msg_pong);
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

	close(sockfd);
	puts("disconnected");
	
	return 0;
}
