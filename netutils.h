#ifndef __NETUTILS_H__
#define __NETUTILS_H__

int tcp_socket_connect_v4mapped_nb(char *ip, int port);
int socket_resolve_and_connect(char *host, int port, int timeout);
void sock_close(int sockfd);
ssize_t sock_read(int sockfd, uint8_t *buf, int len);
int tcp_socket_connect_v4mapped_nb(char *ip, int port);

#endif

