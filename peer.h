#ifndef __PEER_H__
#define __PEER_H__

#include <inttypes.h>

typedef struct peer_s
{
	uint8_t ip[16];
	uint16_t port;
	uint64_t key;
	struct peer_s *left;
	struct peer_s *right;
} peer_t;

peer_t *create_peer(uint8_t *ip, uint16_t port);
peer_t *insert_peer(peer_t *root, peer_t *new);
void dump_peers_tree(peer_t *root);

#endif
