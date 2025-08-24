#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "peer.h"

static uint64_t hash_peer_info(struct in6_addr *addr, uint16_t port)
{
	uint64_t hash = 0;
	for (int i = 0; i < sizeof(addr->s6_addr); i++)
	{
		hash *= 31;
		hash += addr->s6_addr[i];
	}

	hash *= 31;
	hash += port;

	return hash;
}

peer_t *create_peer(struct in6_addr *addr, uint16_t port)
{
	peer_t *p = malloc(sizeof(peer_t));
	memcpy(p->addr.s6_addr, addr, sizeof(struct in6_addr));
	p->port = port;
	p->key = hash_peer_info(addr, port);
	p->queried = 0;
	p->sockfd = 0;
	p->flags = 0;
	p->offset = 0;
	p->left = NULL;
	p->right = NULL;
	return p;
}

peer_t *insert_peer(peer_t *root, peer_t *new, uint8_t *duplicated)
{
	if (root == NULL)
	{
		return new;
	}

	if (new->key < root->key) 		root->left = insert_peer(root->left, new, duplicated);
	else if (new->key > root->key) 	root->right = insert_peer(root->right, new, duplicated);
	else if (new->key == root->key)
	{
		if (duplicated) *duplicated = 1;
	}
	return root;
}

void traverse_peers(peer_t *root, peer_callback_t cb)
{
	if (!root) return;
	
	cb(root);
	
	traverse_peers(root->left, cb);
	traverse_peers(root->right, cb);
}

void dump_peers_tree(peer_t *root)
{
    uint8_t str[INET6_ADDRSTRLEN];

	if (!root) return;
	dump_peers_tree(root->left);

	if (IN6_IS_ADDR_V4MAPPED(&root->addr))
	{
		inet_ntop(AF_INET, root->addr.s6_addr + 12, str, sizeof(str));
	}
	else
	{
		inet_ntop(AF_INET6, root->addr.s6_addr, str, sizeof(str));
	}
	
	printf("peer %016lx: ip %s port %d\n", root->key, str, root->port);

	dump_peers_tree(root->right);
}
