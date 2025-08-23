#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>

#include "common.h"
#include "peer.h"
#include "btc.h"
#include "cJSON.h"

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

		int flags = fcntl(sockfd, F_GETFL, 0);
		fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

		int ret = connect(sockfd, p->ai_addr, p->ai_addrlen);
		if (ret == 0)
		{
			goto connected;
		}
		else if (errno != EINPROGRESS)
		{
			perror("connect");
			close(sockfd);
			continue;
		}

		fd_set wfds;
		FD_ZERO(&wfds);
		FD_SET(sockfd, &wfds);

		struct timeval tv;
		tv.tv_sec = 3;
		tv.tv_usec = 0;

		ret = select(sockfd + 1, NULL, &wfds, NULL, &tv);
		if (ret <= 0)
		{
			puts("connection timed out");
			continue;
		}

		int so_err;
		socklen_t so_len = sizeof(so_err);
		getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_err, &so_len);
		if (so_err != 0)
		{
			errno = so_err;
			perror("getsockopt");
			close(sockfd);
			continue;
		}

connected:
		fcntl(sockfd, F_SETFL, flags);
		puts("connected");
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
	

	uint8_t buf[32768];
	size_t buf_len = sizeof(buf);
	size_t offset = 0;
	int keep_reading = 1;

	write_blob(sockfd, btc_msg_version);

	peer_t *peers = NULL;

	while (keep_reading)
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
				btc_parse_addr(&blob, &peers);
				keep_reading = 0;
			}
			else if(!strncmp(cmd, "addrv2", BTC_HDR_CMD_SIZE))
			{
				puts("received addrv2");
			}
			else if(!strncmp(cmd, "ping", BTC_HDR_CMD_SIZE))
			{
/*
				blob_t *btc_msg_pong = btc_create_msg("pong", p, payload_len);
				write_blob(sockfd, btc_msg_pong);
				free(btc_msg_pong->data);
				free(btc_msg_pong);
*/
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

	close(sockfd);
	puts("disconnected");
	
	return 0;
}
