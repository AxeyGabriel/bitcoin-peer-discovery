#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>

#include "btc_msgs.h"   // btc_create_msg, btc_create_version_payload, btc_parse_addr
#include "peers_tree.h" // peer_t tree code

#define MAX_PEERS 1024
#define TARGET_PEERS 2000
#define MAX_SIMULTANEOUS_CONN 50
#define BUF_SIZE 32768

struct pollfd fds[MAX_PEERS];
peer_t *peer_info[MAX_PEERS];
int nfds = 0;

int tcp_socket_connect_nonblocking(char *ip, int port)
{
    struct sockaddr_in sa;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK);

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip, &sa.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        if (errno != EINPROGRESS) {
            close(sockfd);
            return -1;
        }
    }
    return sockfd;
}

int add_peer_socket(int sockfd, peer_t *peer)
{
    if (nfds >= MAX_PEERS) return -1;
    fds[nfds].fd = sockfd;
    fds[nfds].events = POLLIN | POLLOUT;
    fds[nfds].revents = 0;
    peer_info[nfds] = peer;
    nfds++;
    return 0;
}

peer_t *find_unconnected_peer(peer_t *root)
{
    if (!root) return NULL;
    if (!root->queried) return root;

    peer_t *p;
    if ((p = find_unconnected_peer(root->left))) return p;
    if ((p = find_unconnected_peer(root->right))) return p;
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        printf("USAGE: %s root_ip root_port\n", argv[0]);
        return 1;
    }

    char *root_ip = argv[1];
    int root_port = atoi(argv[2]);

    peer_t *peers_tree_root = peer_new(root_ip, root_port);
    int root_sock = tcp_socket_connect_nonblocking(root_ip, root_port);
    add_peer_socket(root_sock, peers_tree_root);

    blob_t *btc_msg_verack = btc_create_msg("verack", NULL, 0);
    blob_t *btc_msg_getaddr = btc_create_msg("getaddr", NULL, 0);
    blob_t *ver_payload = btc_create_version_payload(root_ip);
    blob_t *btc_msg_version = btc_create_msg("version", ver_payload->data, ver_payload->len);

    write_blob(root_sock, btc_msg_version);
    root_peer->queried = 1;

    uint8_t buf[BUF_SIZE];

    while (peer_count(peers_tree_root) < TARGET_PEERS || nfds > 0) {
        int ret = poll(fds, nfds, 3000);
        if (ret < 0) { perror("poll"); break; }

        for (int i = 0; i < nfds; i++) {
            peer_t *peer = peer_info[i];

            // handle errors
            if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                close(fds[i].fd);
                fds[i] = fds[nfds-1];
                peer_info[i] = peer_info[nfds-1];
                nfds--;
                i--;
                continue;
            }

            // write messages
            if (fds[i].revents & POLLOUT) {
                if (!(peer->flags & PEER_FLAG_SENT_VERSION)) {
                    write_blob(fds[i].fd, btc_msg_version);
                    peer->flags |= PEER_FLAG_SENT_VERSION;
                } else if (!(peer->flags & PEER_FLAG_SENT_VERACK)) {
                    write_blob(fds[i].fd, btc_msg_verack);
                    peer->flags |= PEER_FLAG_SENT_VERACK;
                } else if ((peer->flags & (PEER_FLAG_SENT_VERSION | PEER_FLAG_SENT_VERACK | PEER_FLAG_GOT_VERSION | PEER_FLAG_GOT_VERACK))) {
                    write_blob(fds[i].fd, btc_msg_getaddr);
                }
            }

            // read messages
            if (fds[i].revents & POLLIN) {
                ssize_t n = read(fds[i].fd, buf, sizeof(buf));
                if (n <= 0) continue;

                size_t offset = 0;
                while (offset + BTC_HDR_SIZE <= n) {
                    uint32_t payload_len = *(uint32_t *)(buf + offset + BTC_HDR_OFFSET_PAYLOAD_SIZE);
                    if (offset + BTC_HDR_SIZE + payload_len > n) break;

                    uint8_t *cmd = buf + offset + BTC_HDR_OFFSET_CMD;
                    blob_t blob; blob.data = buf + offset; blob.len = BTC_HDR_SIZE + payload_len;

                    if (!strncmp(cmd, "version", BTC_HDR_CMD_SIZE)) peer->flags |= PEER_FLAG_GOT_VERSION;
                    else if (!strncmp(cmd, "verack", BTC_HDR_CMD_SIZE)) peer->flags |= PEER_FLAG_GOT_VERACK;
                    else if (!strncmp(cmd, "addr", BTC_HDR_CMD_SIZE)) {
                        btc_parse_addr(&blob, &peers_tree_root);
                        peer->queried = 1;
                    }

                    offset += BTC_HDR_SIZE + payload_len;
                }
            }
        }

        // fire new connections to unqueried peers
        peer_t *new_peer;
        while (nfds < MAX_SIMULTANEOUS_CONN && (new_peer = find_unconnected_peer(peers_tree_root))) {
            int s = tcp_socket_connect_nonblocking(new_peer->ip, new_peer->port);
            if (s != -1) add_peer_socket(s, new_peer);
            new_peer->queried = 1;
        }
    }

    dump_peers_tree(peers_tree_root);
    for (int i = 0; i < nfds; i++) close(fds[i].fd);

    printf("Peer discovery finished, total peers: %d\n", peer_count(peers_tree_root));
    return 0;
}

