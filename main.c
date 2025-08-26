#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <time.h>

#include "common.h"
#include "peer.h"
#include "btc.h"
#include "cJSON.h"
#include "netutils.h"

#define MAX_FDS 256
#define BUFSIZE 32768
	
peer_t *peers = NULL;

typedef struct peer_ll {
	peer_t *peer;
	struct peer_ll *next;
	struct peer_ll *prev;
} peer_ll_t;

peer_ll_t *head = NULL, *tail = NULL;

int npeers;
uint8_t buf[MAX_FDS][BUFSIZE];
peer_t *peer_info[MAX_FDS];
int connected = 0;
struct pollfd pollfds[MAX_FDS];
int nfds = 0;
unsigned int total_peers = 0;
unsigned int total_connections_made = 0;

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
	total_connections_made++;

	char str[64];
	in6_addr_port_to_string(&p->addr, htons(p->port), str, sizeof(str));	
	printf("[%d/%d] connected to %s\n", connected, MAX_FDS, str);
}

void add_peer_to_ll(peer_t *p)
{
	peer_ll_t *n = malloc(sizeof(peer_ll_t));
	n->peer = p;
	n->next = NULL;
	n->prev = NULL;

	if (head == NULL)
	{
		head = n;
		tail = n;
	}
	else
	{
		tail->next = n;
		n->prev = tail;
		tail = n;
	}
}

void del_peer_ll_node(peer_ll_t *pll)
{
	if (pll == head)
	{
		head = head->next;
		if (head) head->prev = NULL;
		free(pll);
	}
	else
	{
		pll->prev->next = pll->next;
		pll->next->prev = pll->prev;
		free(pll);
	}
}

void foreach_new_addr(struct in6_addr *addr, int port)
{
	uint8_t dupl = 0;

	if (total_peers >= npeers) return;

#ifdef PEERS_IPV4_ONLY
	if (!IN6_IS_ADDR_V4MAPPED(addr))
    {
		return;
	}
#endif
	peer_t *peer = create_peer(addr, port);
	peers = insert_peer(peers, peer, &dupl);
	if (dupl)
	{
		free(peer);
		return;
	};

	add_peer_to_ll(peer);
	total_peers++;
}

void sock_close_decr(int idx)
{
	char str[64];
	in6_addr_port_to_string(&peer_info[idx]->addr, htons(peer_info[idx]->port), str, sizeof(str));	
	printf("[%d/%d] disconnected peer %s\n", connected, MAX_FDS, str);
	
	sock_close(pollfds[idx].fd);
	
	if (idx != nfds-1)
	{
		pollfds[idx] = pollfds[nfds - 1];
		peer_info[idx] = peer_info[nfds - 1];
		memcpy(buf[idx], buf[nfds-1], BUFSIZE);
	}

	nfds--;
	connected--;
}


int main(int argc, char **argv)
{
	int status;
	char *pa = argv[1];
	int pp = atoi(argv[2]);
	npeers = atoi(argv[3]);
	
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

	resolve_names_and_add_peers(pa, pp, &peers);  	
	
	traverse_peers(peers, add_peer_to_ll);
	
	size_t buf_len = sizeof(buf);

	do
	{
		peer_ll_t *p = head;
		while(p)
		{
			peer_ll_t *tmp = p;
			if (nfds >= MAX_FDS) break;
			connect_to_peer(p->peer);
			p = p->next;
			del_peer_ll_node(tmp);
		}
		
		int ret = poll(pollfds, nfds, 500);
		int len = sizeof(ret);
		if (ret < 0)
		{
			perror("poll");
			break;
		}

		int idx = 0;
		while (idx < nfds)
		{
			peer_t *peer = peer_info[idx];
			if (pollfds[idx].revents & (POLLERR | POLLHUP | POLLNVAL))
			{
				sock_close_decr(idx);
				continue;
			}

			if (pollfds[idx].revents & POLLOUT)
			{
				if (!(peer->flags & PEER_FLAG_SENT_VERSION))
				{
					write_blob(peer->sockfd, btc_msg_version);
					peer->flags |= PEER_FLAG_SENT_VERSION;
					peer->last_command_sent = time(NULL);
				}
				else if ((peer->flags & PEER_FLAG_GOT_VERSION)
					&& !(peer->flags & PEER_FLAG_SENT_VERACK))
				{
					write_blob(peer->sockfd, btc_msg_verack);
					peer->flags |= PEER_FLAG_SENT_VERACK;
					peer->last_command_sent = time(NULL);
				}
				else if ((peer->flags & PEER_FLAG_GOT_VERACK)
					&& !(peer->flags & PEER_FLAG_SENT_GETADDR))
				{
					write_blob(peer->sockfd, btc_msg_getaddr);
					peer->flags |= PEER_FLAG_SENT_GETADDR;
					peer->last_command_sent = time(NULL);
				}
			}

			time_t now = time(NULL);
			if (peer->last_command_sent != 0 && now - peer->last_command_sent >= 4)
			{
				char str[64];
				in6_addr_port_to_string(&peer->addr, htons(peer->port), str, sizeof(str));	
				printf("peer %s timed out\n", str);
				sock_close_decr(idx);
				continue;
			}

			if (pollfds[idx].revents & POLLIN)
			{
				ssize_t n = sock_read(peer->sockfd, buf[idx] + peer->offset, 1);
				//ssize_t n = sock_read(peer->sockfd, buf[idx] + peer->offset, buf_len - peer->offset);
				if (n == -1)
				{
					perror("read");
					continue;
				}

				peer->offset += n;
				size_t pos = 0;
				while (peer->offset - pos >= BTC_HDR_SIZE)
				{
					uint32_t payload_len = *(uint32_t *)(buf[idx] + pos + BTC_HDR_OFFSET_PAYLOAD_SIZE);
					if (peer->offset - pos < payload_len + BTC_HDR_SIZE)
					{
						break;
					}
		
					uint8_t *cmd = buf[idx] + pos + BTC_HDR_OFFSET_CMD;
					uint8_t *p = buf[idx] + pos + BTC_HDR_SIZE;
		
					blob_t blob;
					blob.data = buf[idx] + pos;
					blob.len = payload_len + BTC_HDR_SIZE;
#ifdef DEBUG_DUMP_COMM
					blob_hexdump(&blob, 0);
#endif
					
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
						btc_parse_addr(&blob, foreach_new_addr);
						printf("total peers: %d\n", total_peers);
						sock_close_decr(idx);
						if (idx > 0) idx--;
						break;
					}
					else if(!strncmp(cmd, "addrv2", BTC_HDR_CMD_SIZE))
					{
						puts("received addrv2");
					}
		
					pos += payload_len + 24;
				}

				if (pos > 0)
				{
					memmove(buf[idx], buf[idx] + pos, peer->offset - pos);
					peer->offset -= pos;
				}
			}

			idx++;
		}
	} while (total_peers < npeers && nfds > 0);

	if (peers)
	{
		dump_peers_tree(peers);
		printf("discovered %d peers, made %d conns\n", total_peers, total_connections_made);
	}
	else
	{
		puts("no peers found");
	}

	
	return 0;
}
