#ifndef _NWIF_H
#define _NWIF_H

#include <stdint.h>
#include <stdbool.h>

enum nwif_iface_type {
	NWIF_ETHER_IFACE_TYPE,
	NWIF_TYPE_NR
};

extern bool
nwif_iface_oper_state_isok(uint8_t oper_state);

#endif /* _NWIF_H */
