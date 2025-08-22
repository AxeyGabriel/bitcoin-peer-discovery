#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "cJSON.h"

int tcp_socket_connect(char *host, int port)
{
	int sockfd;
	struct sockaddr_in sa;
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	
	int status = getaddrinfo(host, NULL, &hints, &res);
	if (status != 0)
	{
		printf("error while resolving hostname: %s\n", gai_strerror(status));
		exit(1);
	}

	for (struct addrinfo *p = res; p != NULL; p = p->ai_next)
	{
		char ipstr[INET6_ADDRSTRLEN];
		void *addr;
		if (p->ai_family == AF_INET)
		{
			struct sockaddr_in *addr4 = (struct sockaddr_in *)p->ai_addr;
			addr4->sin_port = htons(port);
			addr = &addr4->sin_addr;
		}
		else
		{
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)p->ai_addr;
			addr6->sin6_port = htons(port);
			addr = &addr6->sin6_addr;
		}
		
		inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
		printf("connecting to %s:%d ...\n", ipstr, port);

		sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sockfd == -1) continue;

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
		{
			perror("failed to connect");
			close(sockfd);
			continue;
		}

		printf("connected\n");
		freeaddrinfo(res);
		return sockfd;
	}

	printf("all options failed. exiting\n");
	freeaddrinfo(res);
	exit(1);
}



int main(int argc, char **argv)
{
	char *pa = argv[1];
	int pp = atoi(argv[2]);
	int sockfd, status;
	
	if (argc < 3)
	{
		printf("USAGE: %s host port\n", argv[0]);
		exit(1);
	}

	printf("Bitcoin peer discovery poc\n"
		"using peer \"%s\" as the root peer\n", pa);

	sockfd = tcp_socket_connect(pa, pp);


	close(sockfd);
	puts("disconnected");
	
	return 0;
}
