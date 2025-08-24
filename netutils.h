#ifndef __NETUTILS_H__
#define __NETUTILS_H__

#include <netinet/in.h>

int resolve_names_and_add_peers(char *host, int port, peer_t **root);
void sock_close(int sockfd);
ssize_t sock_read(int sockfd, uint8_t *buf, int len);
int tcp_socket_connect_v4mapped_nb(struct in6_addr *addr, int port);

#endif

