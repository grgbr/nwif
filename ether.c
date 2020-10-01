#include "ether_priv.h"
#include <string.h>

/******************************************************************************
 * Ethernet interface configuration handling
 ******************************************************************************/

#define nwif_ether_conf_assert_data(_data) \
	nwif_assert((_data)->iface.type == NWIF_ETHER_IFACE_TYPE); \
	nwif_assert(!nwif_iface_conf_data_has_attr(&(_data)->iface, \
	                                           NWIF_SYSPATH_ATTR) || \
	            (unet_check_iface_syspath((_data)->syspath) > 0)); \
	nwif_assert(!nwif_iface_conf_data_has_attr(&(_data)->iface, \
	                                           NWIF_HWADDR_ATTR) || \
	            unet_hwaddr_is_laa(&(_data)->hwaddr)); \
	nwif_assert(!nwif_iface_conf_data_has_attr(&(_data)->iface, \
	                                           NWIF_HWADDR_ATTR) || \
	            unet_hwaddr_is_ucast(&(_data)->hwaddr))

#define nwif_ether_conf_assert(_conf) \
	nwif_ether_conf_assert_data(&(_conf)->data)

const char *
nwif_ether_conf_get_syspath(const struct nwif_ether_conf *conf)
{
	nwif_ether_conf_assert(conf);
	nwif_assert(conf->iface.state != NWIF_IFACE_CONF_EMPTY_STATE);

	if (!nwif_iface_conf_has_attr(&conf->iface, NWIF_SYSPATH_ATTR))
		return NULL;

	return conf->data.syspath;
}

void
nwif_ether_conf_set_syspath(struct nwif_ether_conf *conf,
                            const char             *syspath,
                            size_t                  len)
{
	nwif_ether_conf_assert(conf);
	nwif_assert(unet_check_iface_syspath(syspath) == (ssize_t)len);

	if (nwif_iface_conf_has_attr(&conf->iface, NWIF_SYSPATH_ATTR) &&
	    !strncmp(conf->data.syspath, syspath, sizeof(conf->data.syspath)))
		return;

	memcpy(conf->data.syspath, syspath, len);
	conf->data.syspath[len] = '\0';

	nwif_iface_conf_set_attr(&conf->iface, NWIF_SYSPATH_ATTR);
}

const struct ether_addr *
nwif_ether_conf_get_hwaddr(const struct nwif_ether_conf *conf)
{
	nwif_ether_conf_assert(conf);
	nwif_assert(conf->iface.state != NWIF_IFACE_CONF_EMPTY_STATE);

	if (!nwif_iface_conf_has_attr(&conf->iface, NWIF_HWADDR_ATTR))
		return NULL;

	return &conf->data.hwaddr;
}

void
nwif_ether_conf_set_hwaddr(struct nwif_ether_conf  *conf,
                           const struct ether_addr *hwaddr)
{
	nwif_ether_conf_assert(conf);
	nwif_assert(unet_hwaddr_is_laa(hwaddr) && unet_hwaddr_is_ucast(hwaddr));

	if (nwif_iface_conf_has_attr(&conf->iface, NWIF_HWADDR_ATTR) &&
	    !memcmp(&conf->data.hwaddr, hwaddr, sizeof(*hwaddr)))
		return;

	conf->data.hwaddr = *hwaddr;

	nwif_iface_conf_set_attr(&conf->iface, NWIF_HWADDR_ATTR);
}

void
nwif_ether_conf_clear_hwaddr(struct nwif_ether_conf *conf)
{
	nwif_ether_conf_assert(conf);
	nwif_assert(conf->iface.state != NWIF_IFACE_CONF_EMPTY_STATE);

	nwif_iface_conf_clear_attr(&conf->iface, NWIF_HWADDR_ATTR);
}

static int
nwif_ether_conf_bind_syspath_indx(const struct kvs_chunk *item,
                                  struct kvs_chunk       *skey)
{
	const struct nwif_ether_conf_data *data =
		(struct nwif_ether_conf_data *)item->data;

	nwif_assert(item->size == sizeof(*data));
	nwif_ether_conf_assert_data(data);
	nwif_assert(nwif_iface_conf_data_has_attr(&data->iface,
	                                          NWIF_SYSPATH_ATTR));
	
	skey->data = data->syspath;
	skey->size = strlen(data->syspath);

	return 0;
}

static int
nwif_ether_conf_bind_hwaddr_indx(const struct kvs_chunk *item,
                                 struct kvs_chunk       *skey)
{
	const struct nwif_ether_conf_data *data =
		(struct nwif_ether_conf_data *)item->data;

	nwif_assert(item->size == sizeof(*data));
	nwif_ether_conf_assert_data(data);
	nwif_assert(nwif_iface_conf_data_has_attr(&data->iface,
	                                          NWIF_HWADDR_ATTR));

	skey->data = &data->hwaddr;
	skey->size = sizeof(data->hwaddr);

	return 0;
}

static int
nwif_ether_conf_check_data(uint64_t                           id __unused,
                           const struct nwif_iface_conf_data *data)
{
	nwif_ether_conf_assert_data((struct nwif_ether_conf_data *)data);

	if (!nwif_iface_conf_data_has_attr(data, NWIF_SYSPATH_ATTR))
		return -ENODEV;

	return 0;
}

const struct nwif_iface_conf_impl nwif_ether_conf_impl = {
	.data_size    = sizeof(struct nwif_ether_conf_data),
	.bind_syspath = nwif_ether_conf_bind_syspath_indx,
	.bind_hwaddr  = nwif_ether_conf_bind_hwaddr_indx,
	.check_data   = nwif_ether_conf_check_data
};

struct nwif_ether_conf *
nwif_ether_conf_create(const struct kvs_table *table)
{
	struct nwif_ether_conf *conf;

	conf = malloc(sizeof(*conf));
	if (!conf)
		return NULL;

	nwif_iface_conf_init(&conf->iface, NWIF_ETHER_IFACE_TYPE, table);

	return conf;
}

/******************************************************************************
 * Ethernet interface state handling
 ******************************************************************************/

static bool
nwif_ether_state_probe(const struct nlink_iface *attrs)
{
	nwif_assert(attrs);
	nwif_assert(attrs->type == ARPHRD_ETHER);

	return !attrs->master;
}

static int
nwif_ether_state_fill_attrs(struct nwif_iface_state  *iface,
                            const struct nlink_iface *attrs)
{
	nwif_assert(iface);
	nwif_assert(attrs);
	nwif_assert(attrs->type == ARPHRD_ETHER);

	if (!attrs->ucast_hwaddr ||
	    unet_hwaddr_is_uaa(attrs->ucast_hwaddr) ||
	    unet_hwaddr_is_mcast(attrs->ucast_hwaddr))
		return -EADDRNOTAVAIL;

	((struct nwif_ether_state *) iface)->hwaddr = *attrs->ucast_hwaddr;

	return 0;
}

static int
nwif_ether_state_apply_conf(struct nwif_iface_state      *iface,
                            struct nlmsghdr              *msg,
                            const struct nwif_iface_conf *conf)
{
	nwif_ether_state_assert((struct nwif_ether_state *)iface);
	nwif_assert(msg);
	nwif_ether_conf_assert((struct nwif_ether_conf *)conf);

	const struct ether_addr       *hwaddr;
	const struct nwif_ether_state *ether = (struct nwif_ether_state *)iface;

	hwaddr = nwif_ether_conf_get_hwaddr((struct nwif_ether_conf *)conf);

	if (hwaddr && memcmp(hwaddr, &ether->hwaddr, sizeof(*hwaddr)))
		return nlink_iface_setup_msg_ucast_hwaddr(msg, hwaddr);

	/*
	 * Tell the caller no need to perform apply operation since no data were
	 * modified.
	 */
	return -ECANCELED;
}

const struct nwif_iface_state_impl nwif_ether_state_impl = {
	.arp_type   = ARPHRD_ETHER,
	.probe_type = nwif_ether_state_probe,
	.size       = sizeof(struct nwif_ether_state),
	.fill_attrs = nwif_ether_state_fill_attrs,
	.apply_conf = nwif_ether_state_apply_conf
};
