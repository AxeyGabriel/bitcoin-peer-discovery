#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <netinet/in.h>
#include <time.h>
#include "common.h"
#include "btc.h"

void btc_parse_addr(blob_t *buf, peer_t **root)
{
	uint8_t *payload = buf->data + BTC_HDR_SIZE;
	uint32_t len = buf->len - BTC_HDR_SIZE;

	uint16_t ip_count = payload[0];
	uint16_t offset = 1;

	if (payload[0] == 0xFD)
	{
		ip_count = (payload[2] << 8) | payload[1];
		offset = 3;
	}

	while(ip_count-- && offset+26 <= len)
	{
		offset += 12;
		uint8_t *ip = payload + offset;
		offset += 16;
		uint16_t port = (payload[offset] << 8) | payload[offset + 1];
		offset += 2;
#ifdef PEERS_IPV4_ONLY
		if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)ip))
		{
#endif
			peer_t *peer = create_peer(ip, port);
			*root = insert_peer(*root, peer);
#ifdef PEERS_IPV4_ONLY
		}
#endif
	}
}

/*
 * Calculates the double SHA256 checksum
 * output: out[0..3] containing the 4 bytes of the checksum
 */
static void btc_calculate_checksum(uint8_t *payload, size_t len, uint8_t *out)
{
	uint8_t hash[32][2];
	SHA256(payload, len, hash[0]);
	SHA256(hash[0], 32, hash[1]);
	memcpy(out, hash[1], 4);
}

blob_t *btc_create_version_payload(char *ip)
{
	blob_t *blob = malloc(sizeof(blob_t));
	blob->data = malloc(BTC_MSG_VERSION_SIZE);
	blob->len = BTC_MSG_VERSION_SIZE;
	memset(blob->data, 0, BTC_MSG_VERSION_SIZE);

	SERIALIZE_LE((uint32_t)70015, blob->data + BTC_VER_OFFSET_VERSION);
	SERIALIZE_LE((uint64_t)time(NULL), blob->data + BTC_VER_OFFSET_TIME);

	return blob;
}

/*
 * Creates a binary blob containing the command
 * and the payload, already checksummed and ready
 * to be sent
 */
blob_t *btc_create_msg(const char *cmd, uint8_t *payload, size_t len)
{
	const uint32_t hdr_magic = 0xD9B4BEF9;
	const int hdr_size = 24;
	char *empty_str = "";
	size_t offset = 0;
	
	blob_t *blob = malloc(sizeof(blob_t));
	blob->len = hdr_size + len;
	blob->data = malloc(blob->len);
	memset(blob->data, 0, blob->len);
	SERIALIZE_LE((uint32_t)hdr_magic, blob->data + offset);
	offset += 4;
	strncpy(blob->data + offset, cmd, strlen(cmd));
	offset += 12;
	SERIALIZE_LE((uint32_t)len, blob->data + offset);
	offset += 4;

	if (payload)
	{
		btc_calculate_checksum(payload, len, blob->data + offset);
		offset += 4;
		memcpy(blob->data + offset, payload, len);
	}
	else
	{
		btc_calculate_checksum(empty_str, 0, blob->data + offset);
	}

	return blob;
}
