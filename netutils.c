#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>

#include "common.h"
#include "peer.h"

int resolve_names_and_add_peers(char *host, int port, peer_t **root)
{
	int sockfd;
	struct sockaddr_in sa;
	struct addrinfo hints, *res;
	int count = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	
	int status = getaddrinfo(host, NULL, &hints, &res);
	if (status != 0)
	{
		printf("error while resolving hostname: %s\n", gai_strerror(status));
		return -1;
	}

	for (struct addrinfo *p = res; p != NULL; p = p->ai_next)
	{
		struct in6_addr addr6;
		uint8_t duplicated = 0;

		if (p->ai_family == AF_INET)
		{
			struct sockaddr_in *addr4 = (struct sockaddr_in *)p->ai_addr;
			memset(&addr6, 0, sizeof(addr6));
			addr6.s6_addr[10] = 0xFF;
			addr6.s6_addr[11] = 0xFF;
			memcpy(&addr6.s6_addr[12], 	&addr4->sin_addr, sizeof(addr4->sin_addr));
		}
		else
		{
#ifdef PEERS_IPV4_ONLY
			continue;
#else
			struct sockaddr_in6 *addr = (struct sockaddr_in6 *)p->ai_addr;
			addr6 = addr->sin6_addr;
#endif
		}

		peer_t *new = create_peer(&addr6, port);
		if (!new) continue;

		*root = insert_peer(*root, new, &duplicated);
		if (!duplicated) count++;
	}

	return count;
}

int tcp_socket_connect_v4mapped_nb(struct in6_addr *addr, int port)
{
	int sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		perror("socket");
		return -1;
	}

	int flags = fcntl(sockfd, F_GETFL, 0);
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

	struct sockaddr_in6 sa6;
	memset(&sa6, 0, sizeof(sa6));
	sa6.sin6_family = AF_INET6;
	sa6.sin6_port = htons(port);
	sa6.sin6_addr = *addr;

	if (connect(sockfd, (struct sockaddr *)&sa6, sizeof(sa6)) < 0)
	{
		if (errno != EINPROGRESS)
		{
			perror("connect");
			close(sockfd);
			return -1;
		}
	}

	return sockfd;
}

ssize_t sock_read(int sockfd, uint8_t *buf, int len)
{
	return read(sockfd, buf, len);
}

void sock_close(int sockfd)
{
	close(sockfd);
}

void in6_addr_port_to_string(struct in6_addr *addr, uint16_t port, char *out, size_t out_len) {
    char ipstr[INET6_ADDRSTRLEN];

    if (inet_ntop(AF_INET6, addr, ipstr, sizeof(ipstr)) == NULL) {
        perror("inet_ntop");
        snprintf(out, out_len, "?:%u", port);
        return;
    }

    // For IPv4-mapped IPv6 addresses, you might want to strip ::ffff:
    // Optional: check if addr is IPv4-mapped
    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        struct in_addr ipv4;
        memcpy(&ipv4, &addr->s6_addr[12], sizeof(ipv4));
        if (inet_ntop(AF_INET, &ipv4, ipstr, sizeof(ipstr)) == NULL) {
            perror("inet_ntop");
        }
    }

    snprintf(out, out_len, "%s:%u", ipstr, ntohs(port));
}
