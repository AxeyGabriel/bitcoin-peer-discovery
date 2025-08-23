#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "peer.h"

static uint64_t hash_peer_info(uint8_t *ip, uint16_t port)
{
	uint64_t hash = 0;
	for (int i = 0; i < 16; i++)
	{
		hash *= 31;
		hash += ip[i];
	}

	hash *= 31;
	hash += port;

	return hash;
}

peer_t *create_peer(uint8_t *ip, uint16_t port)
{
	peer_t *p = malloc(sizeof(peer_t));
	memcpy(p->ip, ip, 16);
	p->port = port;
	p->key = hash_peer_info(ip, port);
	p->left = NULL;
	p->right = NULL;
	return p;
}

peer_t *insert_peer(peer_t *root, peer_t *new)
{
	if (root == NULL)
	{
		return new;
	}

	if (new->key < root->key) 		root->left = insert_peer(root->left, new);
	else if (new->key > root->key) 	root->right = insert_peer(root->right, new);

	return root;
}

void dump_peers_tree(peer_t *root)
{
    uint8_t str[INET6_ADDRSTRLEN];

	if (!root) return;
	dump_peers_tree(root->left);

	if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)root->ip))
	{
		inet_ntop(AF_INET, root->ip + 12, str, sizeof(str));
	}
	else
	{
		inet_ntop(AF_INET6, root->ip, str, sizeof(str));
	}
	
	printf("peer %016llx: ip %s port %d\n", root->key, str, root->port);

	dump_peers_tree(root->right);
}
