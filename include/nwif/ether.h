#ifndef _NWIF_ETHER_H
#define _NWIF_ETHER_H

#include <nwif/nwif.h>
#include <kvstore/autorec.h>

struct nwif_iface_conf;
struct nwif_ether_conf;

static inline struct nwif_ether_conf *
nwif_ether_conf_from_iface(const struct nwif_iface_conf *conf)
{
	return (struct nwif_ether_conf *)conf;
}

static inline struct nwif_iface_conf *
nwif_ether_conf_to_iface(const struct nwif_ether_conf *conf)
{
	return (struct nwif_iface_conf *)conf;
}

extern const char *
nwif_ether_conf_get_syspath(const struct nwif_ether_conf *conf);

extern void
nwif_ether_conf_set_syspath(struct nwif_ether_conf *conf,
                            const char             *syspath,
                            size_t                  len);

extern const struct ether_addr *
nwif_ether_conf_get_hwaddr(const struct nwif_ether_conf *conf);

extern void
nwif_ether_conf_set_hwaddr(struct nwif_ether_conf  *conf,
                           const struct ether_addr *hwaddr);

extern struct nwif_ether_conf *
nwif_ether_conf_create(void);

#endif /* _NWIF_ETHER_H */
