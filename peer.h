#ifndef __PEER_H__
#define __PEER_H__

#include <inttypes.h>
#include <netinet/in.h>

#define PEER_FLAG_GOT_VERSION	(1 << 0)
#define PEER_FLAG_GOT_VERACK	(1 << 1)
#define PEER_FLAG_SENT_VERSION	(1 << 2)
#define PEER_FLAG_SENT_VERACK	(1 << 3)
#define PEER_FLAG_SENT_GETADDR	(1 << 4)

typedef struct peer_s
{
	struct in6_addr addr;
	uint16_t port;
	uint64_t key;
	uint8_t queried;
	int sockfd;
	int flags;
	size_t offset;
	struct peer_s *left;
	struct peer_s *right;
} peer_t;

typedef void (*peer_callback_t)(peer_t *p);

peer_t *create_peer(struct in6_addr *addr, uint16_t port);
peer_t *insert_peer(peer_t *root, peer_t *new, uint8_t *duplicated);
void dump_peers_tree(peer_t *root);
void traverse_peers(peer_t *root, peer_callback_t cb);

#endif
