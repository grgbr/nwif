#ifndef _NWIF_H
#define _NWIF_H

#include <stdint.h>
#include <stdbool.h>

struct nwif_repo;
struct nwif_iface;

enum nwif_iface_type {
	NWIF_LOOPBACK_IFACE_TYPE,
	NWIF_ETHER_IFACE_TYPE,
	NWIF_IFACE_TYPE_NR
};

enum nwif_attr_type {
	NWIF_NAME_ATTR        = (1U << 0),
	NWIF_ADMIN_STATE_ATTR = (1U << 1),
	NWIF_MTU_ATTR         = (1U << 2),
	NWIF_SYSPATH_ATTR     = (1U << 3),
	NWIF_HWADDR_ATTR      = (1U << 4),
	NWIF_ATTR_NR
};

#endif /* _NWIF_H */
