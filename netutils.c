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

int socket_resolve_and_connect(char *host, int port, int timeout)
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

		int flags = fcntl(sockfd, F_GETFL, 0);
		fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

		int ret = connect(sockfd, p->ai_addr, p->ai_addrlen);
		if (ret == 0)
		{
			goto connected;
		}
		else if (errno != EINPROGRESS)
		{
			perror("connect");
			close(sockfd);
			continue;
		}

		fd_set wfds;
		FD_ZERO(&wfds);
		FD_SET(sockfd, &wfds);

		struct timeval tv;
		tv.tv_sec = timeout;
		tv.tv_usec = 0;

		ret = select(sockfd + 1, NULL, &wfds, NULL, &tv);
		if (ret <= 0)
		{
			puts("connection timed out");
			continue;
		}

		int so_err;
		socklen_t so_len = sizeof(so_err);
		getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_err, &so_len);
		if (so_err != 0)
		{
			errno = so_err;
			perror("getsockopt");
			close(sockfd);
			continue;
		}

connected:
		//fcntl(sockfd, F_SETFL, flags);
		puts("connected");
		freeaddrinfo(res);
		return sockfd;
	}

	printf("all options failed. exiting\n");
	freeaddrinfo(res);
	exit(1);
}

int tcp_socket_connect_v4mapped_nb(char *ip, int port)
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

	if (inet_pton(AF_INET6, ip, &sa6.sin6_addr) != 1)
	{
		perror("inet_pton");
		close(sockfd);
		return -1;
	}

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
