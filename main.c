#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

#include "common.h"
#include "peer.h"
#include "btc.h"
#include "cJSON.h"
#include "netutils.h"

#define MAX_FDS 2048
	
peer_t *peers = NULL;

uint8_t buf[32768][MAX_FDS];
peer_t *peer_info[MAX_FDS];
int connected = 0;
struct pollfd pollfds[MAX_FDS];
int nfds = 0;

void connect_to_peer(peer_t *p)
{
	if (nfds >= MAX_FDS) return;
	if (p->queried) return;
	if (p->sockfd > 0) return;

	int sockfd = tcp_socket_connect_v4mapped_nb(&p->addr, p->port);

	pollfds[nfds].fd = sockfd;
	pollfds[nfds].events = POLLIN | POLLOUT;
	pollfds[nfds].revents = 0;
	peer_info[nfds] = p;
	p->sockfd = sockfd;
	p->queried = 1;
	nfds++;
	connected++;
}


int main(int argc, char **argv)
{
	int status;
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
	
	traverse_peers(peers, connect_to_peer);
	
	size_t buf_len = sizeof(buf);

	while (total_peers < npeers && nfds > 0)
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
			peer_t *peer = peer_info[fd];
			if (pollfds[fd].revents & (POLLERR | POLLHUP | POLLNVAL))
			{
				sock_close(pollfds[fd].fd);
				pollfds[fd] = pollfds[nfds - 1];
				peer_info[fd] = peer_info[nfds - 1];
				nfds--;
				fd--;
				connected--;
				continue;
			}

			if (pollfds[fd].revents & POLLOUT)
			{
				if (!(peer->flags & PEER_FLAG_SENT_VERSION))
				{
					write_blob(peer->sockfd, btc_msg_version);
					peer->flags |= PEER_FLAG_SENT_VERSION;
				}
				else if ((peer->flags & PEER_FLAG_GOT_VERSION)
					&& !(peer->flags & PEER_FLAG_SENT_VERACK))
				{
					write_blob(peer->sockfd, btc_msg_verack);
					peer->flags |= PEER_FLAG_SENT_VERACK;
				}
				else if ((peer->flags & PEER_FLAG_GOT_VERACK)
					&& !(peer->flags & PEER_FLAG_SENT_GETADDR))
				{
					write_blob(peer->sockfd, btc_msg_getaddr);
					peer->flags |= PEER_FLAG_SENT_GETADDR;
				}
			}

			if (pollfds[fd].revents & POLLIN)
			{
				ssize_t n = sock_read(peer->sockfd, buf[fd] + peer->offset, buf_len - peer->offset);
				if (n == 0)
				{
					continue;
				}
				else if (n == -1)
				{
					perror("read");
					continue;
				}

				peer->offset += n;
				size_t pos = 0;
				while (peer->offset - pos >= BTC_HDR_SIZE)
				{
					uint32_t payload_len = *(uint32_t *)(buf[fd] + pos + BTC_HDR_OFFSET_PAYLOAD_SIZE);
					if (peer->offset - pos < payload_len + BTC_HDR_SIZE)
					{
						break;
					}
		
					uint8_t *cmd = buf[fd] + pos + BTC_HDR_OFFSET_CMD;
					uint8_t *p = buf[fd] + pos + BTC_HDR_SIZE;
		
					blob_t blob;
					blob.data = buf[fd] + pos;
					blob.len = payload_len + BTC_HDR_SIZE;
					//blob_hexdump(&blob, 0);
					
					if(!strncmp(cmd, "version", BTC_HDR_CMD_SIZE))
					{
						peer->flags |= PEER_FLAG_GOT_VERSION;
					}
					else if(!strncmp(cmd, "verack", BTC_HDR_CMD_SIZE))
					{
						peer->flags |= PEER_FLAG_GOT_VERACK;
					}
					else if(!strncmp(cmd, "addr", BTC_HDR_CMD_SIZE))
					{
						total_peers += btc_parse_addr(&blob, &peers);
						printf("%d peers - %d connections\n", total_peers, connected);	
						sock_close(peer->sockfd);
						pollfds[fd] = pollfds[nfds - 1];
						peer_info[fd] = peer_info[nfds - 1];
						nfds--;
						fd--;
						connected--;
					}
					else if(!strncmp(cmd, "addrv2", BTC_HDR_CMD_SIZE))
					{
						puts("received addrv2");
					}
		
					pos += payload_len + 24;
				}

				if (pos > 0)
				{
					memmove(buf[fd], buf[fd] + pos, peer->offset - pos);
					peer->offset -= pos;
				}
			}
		}

		traverse_peers(peers, connect_to_peer);
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
