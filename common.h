#ifndef _NWIF_COMMON_H
#define _NWIF_COMMON_H

#include "nwif/config.h"
#include <nwif/nwif.h>

#if defined(CONFIG_NWIF_ASSERT)

#include <utils/assert.h>

#define nwif_assert(_expr) \
	uassert("nwif", _expr)

#else  /* !defined(CONFIG_NWIF_ASSERT) */

#define nwif_assert(_expr)

#endif /* defined(CONFIG_NWIF_ASSERT) */

extern int
nwif_iface_probe_sysid(const char *syspath);

/******************************************************************************
 * Base interface state utils
 ******************************************************************************/

struct nwif_iface_state {
	int sys_id;
};

static inline int
nwif_iface_state_get_id(const struct nwif_iface_state *state)
{
	nwif_assert(state);
	nwif_assert(state->sys_id > 0);

	return state->sys_id;
}

static inline void
nwif_iface_state_init(struct nwif_iface_state *state, int sys_id)
{
	nwif_assert(state);
	nwif_assert(sys_id > 0);

	state->sys_id = sys_id;
}

#endif /* _NWIF_COMMON_H */
