#ifndef __PEER_H__
#define __PEER_H__

#include <inttypes.h>
#include <netinet/in.h>

typedef struct peer_s
{
	struct in6_addr addr;
	uint16_t port;
	uint64_t key;
	uint8_t queried;
	struct peer_s *left;
	struct peer_s *right;
} peer_t;

peer_t *create_peer(struct in6_addr *addr, uint16_t port);
peer_t *insert_peer(peer_t *root, peer_t *new, uint8_t *duplicated);
void dump_peers_tree(peer_t *root);
peer_t* find_unqueried(peer_t *root);

#endif
