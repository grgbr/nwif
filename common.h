#ifndef _NWIF_COMMON_H
#define _NWIF_COMMON_H

#include "nwif/config.h"
#include <nwif/nwif.h>
#include <karn/pavl.h>

#if defined(CONFIG_NWIF_ASSERT)

#include <utils/assert.h>

#define nwif_assert(_expr) \
	uassert("nwif", _expr)

#else  /* !defined(CONFIG_NWIF_ASSERT) */

#define nwif_assert(_expr)

#endif /* defined(CONFIG_NWIF_ASSERT) */

enum nwif_class {
	NWIF_IFACE_CLASS,
	NWIF_ADDR_CLASS,
	NWIF_ROUTE_CLASS,
	NWIF_CLASS_NR
};

extern int
nwif_iface_probe_sysid(const char *syspath);

#endif /* _NWIF_COMMON_H */
