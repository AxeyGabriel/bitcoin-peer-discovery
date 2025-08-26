#ifndef __BTC_H__
#define __BTC_H__

#include <inttypes.h>
#include "peer.h"

#define BTC_HDR_OFFSET_MAGIC		0
#define BTC_HDR_OFFSET_CMD			4
#define BTC_HDR_OFFSET_PAYLOAD_SIZE	16
#define BTC_HDR_OFFSET_CHECKSUM		20
#define BTC_HDR_SIZE				24
#define BTC_HDR_CMD_SIZE			12

#define BTC_VER_OFFSET_VERSION 		0
#define BTC_VER_OFFSET_TIME 		12
#define BTC_MSG_VERSION_SIZE		86

blob_t *btc_create_msg(const char *cmd, blob_t *blob);
blob_t *btc_create_version_payload(void);

int btc_parse_addr(blob_t *buf, void (*cb_foreach_addr)(struct in6_addr *addr, int));

#endif
