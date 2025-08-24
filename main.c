#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

#include "common.h"
#include "peer.h"
#include "btc.h"
#include "cJSON.h"
#include "netutils.h"

#define MAX_FDS 1024
	
peer_t *peers = NULL;

struct pollfd pollfds[MAX_FDS];
struct pollfd pollsockfd;
int nfds = 0;
peer_t *peer_info[MAX_FDS];

int add_peer_socket(int sockfd, peer_t *peer)
{
	if (nfds >= MAX_FDS)	return -1;
	pollfds[nfds].fd = sockfd;
	pollfds[nfds].events = POLLIN | POLLOUT;
	pollfds[nfds].revents = 0;
	peer_info[nfds] = peer;
	nfds++;
	return 0;
}


int main(int argc, char **argv)
{
	int sockfd, status;
	char *pa = argv[1];
	int pp = atoi(argv[2]);
	int npeers = atoi(argv[3]);
	
	if (argc < 3)
	{
		printf("USAGE: %s host port\n", argv[0]);
		exit(1);
	}

	printf("Bitcoin peer discovery poc\n"
		"using peer \"%s\" as the root peer\n", pa);

	/*
 	 * Pre allocate all needed messages
 	 */	
	blob_t *btc_msg_version_payload = btc_create_version_payload();
	blob_t *btc_msg_version = btc_create_msg("version",
			btc_msg_version_payload->data, btc_msg_version_payload->len);
	blob_t *btc_msg_verack = btc_create_msg("verack", NULL, 0);
	blob_t *btc_msg_getaddr = btc_create_msg("getaddr", NULL, 0);

	unsigned int total_peers = 0;
	total_peers += resolve_names_and_add_peers(pa, pp, &peers);  	
	
	peer_t *peer;
	dump_peers_tree(peers);
	while((peer = find_unqueried(peers)) != NULL)
	{
		int sockfd = tcp_socket_connect_v4mapped_nb(&peer->addr, peer->port);
		add_peer_socket(sockfd, peer);
	}
	exit(1);

	
	uint8_t peer_flags = 0;
#define PEER_FLAG_GOT_VERSION	(1 << 0)
#define PEER_FLAG_GOT_VERACK	(1 << 1)
#define PEER_FLAG_SENT_VERSION	(1 << 2)
#define PEER_FLAG_SENT_VERACK	(1 << 3)
#define PEER_FLAG_SENT_GETADDR	(1 << 4)

	
	uint8_t buf[32768];
	size_t buf_len = sizeof(buf);
	size_t offset = 0;

	while (total_peers < 10)
	{
		int ret = poll(pollfds, nfds, 3000);
		int len = sizeof(ret);
		if (ret < 0)
		{
			perror("poll");
			break;
		}

		for (int fd = 0; fd < nfds; fd++)
		{
			if (pollfds[fd].revents & (POLLERR | POLLHUP | POLLNVAL))
			{
				sock_close(pollfds[fd].fd);
				pollfds[fd] = pollfds[nfds - 1];
				nfds--;
				fd--;
				continue;
			}	
		}

		if (pollsockfd.revents & POLLOUT)
		{
			if (!(peer_flags & PEER_FLAG_SENT_VERSION))
			{
				write_blob(sockfd, btc_msg_version);
				peer_flags |= PEER_FLAG_SENT_VERSION;
			}
			else if ((peer_flags & PEER_FLAG_GOT_VERSION)
				&& !(peer_flags & PEER_FLAG_SENT_VERACK))
			{
				write_blob(sockfd, btc_msg_verack);
				peer_flags |= PEER_FLAG_SENT_VERACK;
			}
			else if ((peer_flags & PEER_FLAG_GOT_VERACK)
				&& !(peer_flags & PEER_FLAG_SENT_GETADDR))
			{
				write_blob(sockfd, btc_msg_getaddr);
				peer_flags |= PEER_FLAG_SENT_GETADDR;
			}
		}

		if (pollsockfd.revents & POLLIN)
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
					peer_flags |= PEER_FLAG_GOT_VERSION;
				}
				else if(!strncmp(cmd, "verack", BTC_HDR_CMD_SIZE))
				{
					peer_flags |= PEER_FLAG_GOT_VERACK;
				}
				else if(!strncmp(cmd, "addr", BTC_HDR_CMD_SIZE))
				{
					total_peers += btc_parse_addr(&blob, &peers);
					sock_close(sockfd);
					puts("disconnected");
				}
				else if(!strncmp(cmd, "addrv2", BTC_HDR_CMD_SIZE))
				{
					puts("received addrv2");
				}
	
				pos += payload_len + 24;
			}

			if (pos > 0)
			{
				memmove(buf, buf + pos, offset - pos);
				offset -= pos;
			}
		}
	}

	if (peers)
	{
		dump_peers_tree(peers);
		printf("discovered %d peers\n", total_peers);
	}
	else
	{
		puts("no peers found");
	}

	
	return 0;
}
