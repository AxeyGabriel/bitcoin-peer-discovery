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

int resolve_names(char *host, int port, void (*cb_foreach_addr)(struct in6_addr *addr, int))
{
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

		cb_foreach_addr(&addr6, port);
	}

	return count;
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
