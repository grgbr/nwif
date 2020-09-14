#ifndef _NWIF_H
#define _NWIF_H

#include <stdint.h>
#include <stdbool.h>

enum nwif_iface_type {
	NWIF_ETHER_IFACE_TYPE,
	NWIF_TYPE_NR
};

enum nwif_attr_type {
	NWIF_NAME_ATTR       = (1U << 0),
	NWIF_OPER_STATE_ATTR = (1U << 1),
	NWIF_MTU_ATTR        = (1U << 2),
	NWIF_SYSPATH_ATTR    = (1U << 3),
	NWIF_HWADDR_ATTR     = (1U << 4),
	NWIF_ATTR_NR
};

extern bool
nwif_iface_oper_state_isok(uint8_t oper_state);

#endif /* _NWIF_H */
