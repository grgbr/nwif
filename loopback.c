#include "iface_priv.h"

static bool
nwif_loopback_state_probe(const struct nlink_iface *attrs)
{
	nwif_assert(attrs);
	nwif_assert(attrs->type == ARPHRD_LOOPBACK);

	return !attrs->master;
}

static int
nwif_loopback_fill_attrs(struct nwif_iface_state  *iface,
                         const struct nlink_iface *attrs)
{
	nwif_assert(iface);
	nwif_assert(attrs);

	if (attrs->oper_state == IF_OPER_UNKNOWN)
		/*
		 * When UP, loopback interfaces expose an unknown operational
		 * state (unless requested down, they are always on).
		 */
		iface->oper_state = IF_OPER_UP;

	return 0;
}

static int
nwif_loopback_state_apply_conf(struct nwif_iface_state      *state __unused,
                               struct nlmsghdr              *msg __unused,
                               const struct nwif_iface_conf *conf __unused)
{
	return 0;
}

const struct nwif_iface_state_impl nwif_loopback_state_impl = {
	.arp_type   = ARPHRD_LOOPBACK,
	.probe_type = nwif_loopback_state_probe,
	.size       = sizeof(struct nwif_iface_state),
	.fill_attrs = nwif_loopback_fill_attrs,
	.apply_conf = nwif_loopback_state_apply_conf
};
