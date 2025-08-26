#ifndef __NETUTILS_H__
#define __NETUTILS_H__

#include <netinet/in.h>

int resolve_names(char *host, int port, void (*cb_foreach_addr)(struct in6_addr *addr, int));
void in6_addr_port_to_string(struct in6_addr *addr, uint16_t port, char *out, size_t out_len);

#endif

