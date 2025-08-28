#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/timerfd.h>

#include "common.h"
#include "peer.h"
#include "btc.h"
#include "netutils.h"

#define CONN_POOL_SIZE 	32
#define CONN_QUEUE_SIZE (512)
#define BUFSIZE 		0x02000000
#define POLL_TIME_MS 	100
#define PEER_TIMEOUT_SECS 2

#define PEER_FLAG_GOT_VERSION	(1 << 0)
#define PEER_FLAG_GOT_VERACK	(1 << 1)
#define PEER_FLAG_SENT_VERSION	(1 << 2)
#define PEER_FLAG_SENT_VERACK	(1 << 3)
#define PEER_FLAG_SENT_GETADDR	(1 << 4)
#define PEER_FLAG_EXPECT_DATA	(1 << 5)
#define PEER_FLAG_IGNORE_DATA	(1 << 6)
#define PEER_FLAG_CONNECTED		(1 << 7)
	
typedef struct conn_queue_s {
	peer_t *peer[CONN_QUEUE_SIZE];
	size_t head;
	size_t tail;
	size_t size;
} conn_queue_t;

typedef struct peer_conn_s {
	peer_t *peer;
	uint8_t buf[BUFSIZE];
	uint8_t txbuf[256];
	uint16_t txoffset;
	uint16_t txlen;
	struct pollfd *pfd;
	time_t time;
	size_t offset;
	size_t payload_len;
	int flags;
} peer_conn_t;

conn_queue_t conn_queue;
peer_conn_t peer_conn[CONN_POOL_SIZE];
struct pollfd peer_conn_fd[CONN_POOL_SIZE];
int conns = 0;

int npeers;
int connected = 0;
peer_t *peers = NULL;

int total_peers = 0;
int total_connections_made = 0;

int connect_to_peer(peer_t *p)
{
	int sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		perror("socket");
		return -2;
	}

	int flags = fcntl(sockfd, F_GETFL, 0);
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

	struct sockaddr_in6 sa6;
	memset(&sa6, 0, sizeof(sa6));
	sa6.sin6_family = AF_INET6;
	sa6.sin6_port = htons(p->port);
	sa6.sin6_addr = p->addr;

	if (connect(sockfd, (struct sockaddr *)&sa6, sizeof(sa6)) <= 0)
	{
		if (errno != EINPROGRESS)
		{
			perror("connect");
			close(sockfd);
			return -3;
		}
	}

	int i;
	for (i = 0; i < CONN_POOL_SIZE; i++)
	{
		if (peer_conn_fd[i].fd == -1)
		{
			break;
		}
	}

	peer_conn[i].pfd = &peer_conn_fd[i];
	peer_conn[i].pfd->fd = sockfd;
	peer_conn[i].pfd->events = POLLIN | POLLOUT;
	peer_conn[i].pfd->revents = 0;
	peer_conn[i].peer = p;
	peer_conn[i].time = time(NULL);
	peer_conn[i].offset = 0;
	peer_conn[i].flags = 0;
	peer_conn[i].txoffset = 0;
	peer_conn[i].txlen = 0;
	conns++;

	connected++;
	total_connections_made++;

	char str[64];
	in6_addr_port_to_string(&p->addr, htons(p->port), str, sizeof(str));	
	printf("[%d/%d] trying to connect to to %s\n", connected, CONN_POOL_SIZE, str);

	return 0;
}

peer_t *conn_dequeue(void)
{
	if (conn_queue.size == 0) return NULL;

	peer_t *p = conn_queue.peer[conn_queue.tail];
	conn_queue.tail++;
	conn_queue.tail %= CONN_QUEUE_SIZE;
	conn_queue.size--;

	return p;
}

void conn_enqueue(peer_t *p)
{
	if (conn_queue.size == CONN_QUEUE_SIZE)
	{
		conn_queue.tail++;
		conn_queue.tail %= CONN_QUEUE_SIZE;
		conn_queue.size--;
	}

	conn_queue.peer[conn_queue.head] = p;
	conn_queue.head++;
	conn_queue.head %= CONN_QUEUE_SIZE;
	conn_queue.size++;
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

	conn_enqueue(peer);
	total_peers++;
}

void close_connection(peer_conn_t *pc, int idx)
{
	char str[64];
	in6_addr_port_to_string(&pc->peer->addr, htons(pc->peer->port), str, sizeof(str));	
	printf("[%d/%d] disconnected peer %s\n", connected, CONN_POOL_SIZE, str);
	
	close(peer_conn_fd[idx].fd);

	peer_conn[idx].peer = NULL;
	peer_conn_fd[idx].fd = -1;
	
	conns--;
	connected--;
}


int main(int argc, char **argv)
{
	char *pa = argv[1];
	int pp = atoi(argv[2]);
	npeers = atoi(argv[3]);
	char str[64];
	
	if (argc < 3)
	{
		printf("USAGE: %s host port\n", argv[0]);
		exit(1);
	}

	printf("Bitcoin peer discovery poc\n"
		"using peer \"%s\" as the root peer\n", pa);

	memset(&conn_queue, 0, sizeof(conn_queue));

	/*
 	 * Pre allocate all needed messages
 	 */	
	blob_t *btc_msg_version_payload = btc_create_version_payload();
	blob_t *btc_msg_version = btc_create_msg("version", btc_msg_version_payload);
	blob_t *btc_msg_verack = btc_create_msg("verack", NULL);
	blob_t *btc_msg_getaddr = btc_create_msg("getaddr", NULL);

	resolve_names(pa, pp, &foreach_new_addr);
	
	for (int i = 0; i < CONN_POOL_SIZE; i++)
	{
		peer_conn_fd[i].fd = -1;
	}

	time_t report = time(NULL);

	do
	{
		/*
 		 * Test if there are pending connections
 		 * then connect them if we have free slots
 		 */
		while(conn_queue.size > 0)
		{
			if (conns >= CONN_POOL_SIZE)
			{
				// No free slots available
				break;
			}

			peer_t *p = conn_dequeue();
			if (!p) break;

			int c = connect_to_peer(p);
			if (c != 0)
			{
				printf("connect_to_peer failed: %d\n", c);
			}
		}

		if (time(NULL) - report >= 1)
		{
			report = time(NULL);
			printf("stats: %d peers; conn_queue size=%ld; connected=%d\n", total_peers, conn_queue.size, connected);
		}
		
		int ret = poll(peer_conn_fd, CONN_POOL_SIZE, POLL_TIME_MS);
		if (ret < 0)
		{
			perror("poll");
			break;
		}

		int idx = 0;
		while (idx < CONN_POOL_SIZE)
		{
			peer_conn_t *pc = &peer_conn[idx];
			peer_t *peer = pc->peer;
			struct pollfd *pfd = pc->pfd;

			if (!peer || pfd->fd == -1)
			{
				idx++;
				continue;
			}

			if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL))
			{
				in6_addr_port_to_string(&peer->addr, htons(peer->port), str, sizeof(str));	
				
				if (pfd->revents & POLLERR)
				{
					int err = 0;
					
					socklen_t len = sizeof(err);
					getsockopt(pfd->fd, SOL_SOCKET, SO_ERROR, &err, &len);
								printf("peer %s: %s\n",
								str, strerror(err));
				}
				if (pfd->revents & POLLHUP)
				{
					printf("peer %s closed connection\n", str);
				}
				if (pfd->revents & POLLNVAL)
				{
					printf("peer %s panic: fd not open\n", str);
				}

				close_connection(pc, idx);
				idx++;
				continue;
			}

			if (pfd->revents & POLLOUT)
			{
				if (!(pc->flags & PEER_FLAG_CONNECTED))
				{
					int err = 0;
					socklen_t len = sizeof(err);
					if (getsockopt(pfd->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
					{
					    perror("getsockopt");
						close_connection(pc, idx);
						idx++;
						continue;
					}
					if (err == 0)
					{
						in6_addr_port_to_string(&peer->addr, htons(peer->port), str, sizeof(str));	
						printf("peer %s connected\n", str);
						pc->flags |= PEER_FLAG_CONNECTED;
					}
					else
					{
						in6_addr_port_to_string(&peer->addr, htons(peer->port), str, sizeof(str));	
						printf("peer %s failed to connect: %s\n", str, strerror(err));
						close_connection(pc, idx);
						idx++;
						continue;
					}
				}

				if (!(pc->flags & PEER_FLAG_CONNECTED))
				{
					idx++;
					continue;
				}


				if (!(pc->flags & PEER_FLAG_SENT_VERSION))
				{
					memcpy(pc->txbuf, btc_msg_version->data, btc_msg_version->len);
					pc->txlen = btc_msg_version->len;
					pc->flags |= PEER_FLAG_SENT_VERSION;
					pc->time = time(NULL);
				}
				else if ((pc->flags & PEER_FLAG_GOT_VERSION)
					&& !(pc->flags & PEER_FLAG_SENT_VERACK))
				{
					memcpy(pc->txbuf, btc_msg_verack->data, btc_msg_verack->len);
					pc->txlen = btc_msg_verack->len;
					pc->flags |= PEER_FLAG_SENT_VERACK;
					pc->time = time(NULL);
				}
				else if ((pc->flags & PEER_FLAG_GOT_VERACK)
					&& !(pc->flags & PEER_FLAG_SENT_GETADDR))
				{
					memcpy(pc->txbuf, btc_msg_getaddr->data, btc_msg_getaddr->len);
					pc->txlen = btc_msg_getaddr->len;
					pc->flags |= PEER_FLAG_SENT_GETADDR;
					pc->time = time(NULL);
				}

				if (pc->txlen > 0)
				{
					ssize_t n = write(pfd->fd, pc->txbuf + pc->txoffset, pc->txlen - pc->txoffset);
					if (n > 0)
					{
						pc->txoffset += n;
						if (pc->txoffset == pc->txlen)
						{
#ifdef DEBUG
							blob_t txdata;
							txdata.data = pc->txbuf;
							txdata.len = pc->txlen;
							blob_hexdump(&txdata, 1);
#endif
							pc->txoffset = 0;
							pc->txlen = 0;
						}
					}
					else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
					{
						perror("write");
						close_connection(pc, idx);
						idx++;
						continue;
					}
				}
			}

			time_t now = time(NULL);
			if (now - pc->time >= PEER_TIMEOUT_SECS)
			{
				in6_addr_port_to_string(&peer->addr, htons(peer->port), str, sizeof(str));	
				printf("peer %s timed out\n", str);
				close_connection(pc, idx);
				idx++;
				continue;
			}

			if (pfd->revents & POLLIN)
			{
				size_t expect;
				if (pc->flags & PEER_FLAG_EXPECT_DATA)
				{
					expect = pc->payload_len - pc->offset + BTC_HDR_SIZE;
				}
				else
				{
					expect = BTC_HDR_SIZE - pc->offset;
				}
				
				ssize_t n = recv(pfd->fd, pc->buf + pc->offset, expect, MSG_DONTWAIT);
				if (n <= 0)
				{
					if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS)
					{
						continue;
					}

					perror("read");
					close_connection(pc, idx);
					idx++;
					continue;
				}
				
				if (n > 0)
				{
					pc->offset += n;

					if (pc->offset >= BTC_HDR_SIZE && !(pc->flags & PEER_FLAG_EXPECT_DATA))
					{
						uint32_t payload_len;
						memcpy(&payload_len, pc->buf + BTC_HDR_OFFSET_PAYLOAD_SIZE, sizeof(payload_len));
						payload_len = le32toh(payload_len);
						if (payload_len > BUFSIZE - BTC_HDR_SIZE)
						{
							in6_addr_port_to_string(&peer->addr, htons(peer->port), str, sizeof(str));	
							printf("peer %s:%d sent invalid payload size: %d. flags=%d. aborting\n", str, peer->port, payload_len, pc->flags);
							blob_t blob;
							blob.data = pc->buf;
							blob.len = BTC_HDR_SIZE;
							blob_hexdump(&blob, 0);
							close_connection(pc, idx);
							idx++;
							continue;
						}

						pc->payload_len = payload_len;

						uint8_t *cmd = pc->buf + BTC_HDR_OFFSET_CMD;

						if(!strncmp((char *)cmd, "version", BTC_HDR_CMD_SIZE))
						{
							pc->flags |= PEER_FLAG_EXPECT_DATA;
						}
						else if(!strncmp((char *)cmd, "verack", BTC_HDR_CMD_SIZE))
						{
							pc->flags |= PEER_FLAG_GOT_VERACK;
							pc->flags &= ~PEER_FLAG_EXPECT_DATA;
						}
						else if(!strncmp((char *)cmd, "addr", BTC_HDR_CMD_SIZE))
						{
							pc->flags |= PEER_FLAG_EXPECT_DATA;
						}
						else
						{
							if (payload_len == 0)
							{
								pc->flags &= ~PEER_FLAG_EXPECT_DATA;
							}
							else
							{
								pc->flags |= PEER_FLAG_IGNORE_DATA;
								pc->flags |= PEER_FLAG_EXPECT_DATA;
							}
						}

#ifdef DEBUG
						if (!(pc->flags & PEER_FLAG_EXPECT_DATA))
						{
							blob_t blob;
							blob.data = pc->buf;
							blob.len = BTC_HDR_SIZE;
							blob_hexdump(&blob, 0);
						}
#endif
					}
					
					if (pc->offset >= (pc->payload_len + BTC_HDR_SIZE) && (pc->flags & PEER_FLAG_EXPECT_DATA))
					{
						pc->flags &= ~PEER_FLAG_EXPECT_DATA;

						blob_t blob;
						blob.data = pc->buf;
						blob.len = pc->payload_len + BTC_HDR_SIZE;
#ifdef DEBUG
						blob_hexdump(&blob, 0);
#endif

						if (pc->flags & PEER_FLAG_IGNORE_DATA)
						{
							pc->flags &= ~PEER_FLAG_IGNORE_DATA;
							goto dataend;
						}

						if (pc->flags & PEER_FLAG_SENT_VERSION
							&& !(pc->flags & PEER_FLAG_GOT_VERSION))
						{
							pc->flags |= PEER_FLAG_GOT_VERSION;
						}

						if (pc->flags & PEER_FLAG_SENT_GETADDR)
						{
							btc_parse_addr(&blob, foreach_new_addr);
							close_connection(pc, idx);
							idx++;
						}
dataend:
					}
					
					if (!(pc->flags & PEER_FLAG_EXPECT_DATA))
					{
						pc->offset = 0;
					}
				}
			}

			idx++;
		}
	} while (total_peers < npeers && (conns || conn_queue.size));

	if (peers)
	{
		dump_peers_tree(peers);
		printf("discovered %d peers, made %d conns\n", total_peers, total_connections_made);
	}
	else
	{
		puts("no peers found");
	}
	
	free(btc_msg_version_payload);
	free(btc_msg_version);
	free(btc_msg_verack);
	free(btc_msg_getaddr);
	
	return 0;
}
