#ifndef __NETUTILS_H__
#define __NETUTILS_H__

int tcp_socket_connect(char *host, int port);
void sock_close(int sockfd);
ssize_t sock_read(int sockfd, uint8_t *buf, int len);

#endif

