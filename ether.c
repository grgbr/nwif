#include <nwif/ether.h>
#include "common.h"
#include <nwif/conf.h>
#include <nlink/iface.h>
#include <utils/net.h>
#include <string.h>
#include <errno.h>
#include <net/if_arp.h>
#include <net/ethernet.h>

struct nwif_ether_conf_data {
	struct nwif_iface_conf_data iface;
	char                        syspath[UNET_IFACE_SYSPATH_MAX];
	struct ether_addr           hwaddr;
};

struct nwif_ether_conf {
	struct nwif_iface_conf      iface;
	struct nwif_ether_conf_data data;
};

#define nwif_ether_conf_assert(_conf) \
	nwif_assert((_conf)->data.iface.type == NWIF_ETHER_IFACE_TYPE); \
	nwif_assert(!nwif_iface_conf_has_attr(&(_conf)->iface, \
	                                      NWIF_SYSPATH_ATTR) || \
	            (unet_check_iface_syspath((_conf)->data.syspath) > 0)); \
	nwif_assert(!nwif_iface_conf_has_attr(&(_conf)->iface, \
	                                      NWIF_HWADDR_ATTR) || \
	            unet_hwaddr_is_laa(&(_conf)->data.hwaddr)); \
	nwif_assert(!nwif_iface_conf_has_attr(&(_conf)->iface, \
	                                      NWIF_HWADDR_ATTR) || \
	            unet_hwaddr_is_ucast(&(_conf)->data.hwaddr))

#define nwif_ether_conf_assert_get(_conf) \
	nwif_assert((_conf)->iface.state != NWIF_IFACE_CONF_EMPTY_STATE); \
	nwif_assert((_conf)->iface.state != NWIF_IFACE_CONF_FAIL_STATE); \
	nwif_ether_conf_assert(_conf)

#define nwif_ether_conf_assert_set(_conf) \
	nwif_assert((_conf)->iface.state != NWIF_IFACE_CONF_FAIL_STATE); \
	nwif_ether_conf_assert(_conf)

const char *
nwif_ether_conf_get_syspath(const struct nwif_ether_conf *conf)
{
	nwif_ether_conf_assert_get(conf);

	if (!nwif_iface_conf_has_attr(&conf->iface, NWIF_SYSPATH_ATTR))
		return NULL;

	return conf->data.syspath;
}

void
nwif_ether_conf_set_syspath(struct nwif_ether_conf *conf,
                            const char             *syspath,
                            size_t                  len)
{
	nwif_ether_conf_assert_set(conf);
	nwif_assert(unet_check_iface_syspath(syspath) == (ssize_t)len);

	memcpy(conf->data.syspath, syspath, len);
	conf->data.syspath[len] = '\0';

	nwif_iface_conf_set_attr(&conf->iface, NWIF_SYSPATH_ATTR);
}

const struct ether_addr *
nwif_ether_conf_get_hwaddr(const struct nwif_ether_conf *conf)
{
	nwif_ether_conf_assert_get(conf);

	if (!nwif_iface_conf_has_attr(&conf->iface, NWIF_HWADDR_ATTR))
		return NULL;

	return &conf->data.hwaddr;
}

void
nwif_ether_conf_set_hwaddr(struct nwif_ether_conf  *conf,
                           const struct ether_addr *hwaddr)
{
	nwif_ether_conf_assert_set(conf);
	nwif_assert(unet_hwaddr_is_laa(hwaddr) && unet_hwaddr_is_ucast(hwaddr));

	conf->data.hwaddr = *hwaddr;

	nwif_iface_conf_set_attr(&conf->iface, NWIF_HWADDR_ATTR);
}

int
nwif_ether_conf_save(struct nwif_iface_conf *conf,
                     const struct kvs_xact  *xact,
                     struct nwif_conf_repo  *repo)
{
	nwif_assert(conf);

	const struct nwif_ether_conf_data *data;
	int                                err;

	data = &((struct nwif_ether_conf *)conf)->data;

	nwif_assert(!nwif_iface_conf_has_attr(conf, NWIF_SYSPATH_ATTR) ||
	            unet_check_iface_syspath(data->syspath) > 0);
	nwif_assert(!nwif_iface_conf_has_attr(conf, NWIF_HWADDR_ATTR) ||
	            unet_hwaddr_is_laa(&data->hwaddr));
	nwif_assert(!nwif_iface_conf_has_attr(conf, NWIF_HWADDR_ATTR) ||
	            unet_hwaddr_is_ucast(&data->hwaddr));

	if (!nwif_iface_conf_has_attr(conf, NWIF_SYSPATH_ATTR))
		return -ENODEV;

	if (!kvs_autoidx_id_isok(conf->id)) {
		err = kvs_autoidx_add(&repo->ifaces.data,
		                      xact,
		                      &conf->id,
		                      data,
		                      sizeof(*data));
		kvs_assert(err || kvs_autoidx_id_isok(conf->id));
	}
	else
		err = kvs_autoidx_update(&repo->ifaces.data,
		                         xact,
		                         conf->id,
		                         data,
		                         sizeof(*data));

	return err;
}

int
nwif_ether_conf_load_from_desc(struct nwif_iface_conf        *conf,
                               const struct kvs_autoidx_desc *desc)
{
	const struct nwif_ether_conf_data *data;
	int                                err;

	err = nwif_iface_conf_check_data(desc,
	                                 NWIF_ETHER_IFACE_TYPE,
	                                 sizeof(*data));
	if (err)
		return err;

	data = (struct nwif_ether_conf_data *)desc->data;

	if (!nwif_iface_conf_data_has_attr(&data->iface, NWIF_SYSPATH_ATTR) ||
	    (unet_check_iface_syspath(data->syspath) < 0))
		return -EBADMSG;

	if (nwif_iface_conf_data_has_attr(&data->iface, NWIF_HWADDR_ATTR) &&
	    (unet_hwaddr_is_uaa(&data->hwaddr) ||
	     unet_hwaddr_is_mcast(&data->hwaddr)))
		return -EBADMSG;

	conf->state = NWIF_IFACE_CONF_CLEAN_STATE;
	conf->id = desc->id;
	*(struct nwif_ether_conf_data *)conf->data = *data;

	return 0;
}

struct nwif_iface_conf *
nwif_ether_conf_create_from_desc(const struct kvs_autoidx_desc *desc)
{
	struct nwif_iface_conf *conf;
	int                     err;

	conf = malloc(sizeof(struct nwif_ether_conf));
	if (!conf)
		return NULL;

	err = nwif_ether_conf_load_from_desc(conf, desc);
	if (err)
		goto free;

	return conf;

free:
	free(conf);

	errno = -err;
	return NULL;
}

struct nwif_ether_conf *
nwif_ether_conf_create(void)
{
	struct nwif_ether_conf *conf;

	conf = malloc(sizeof(*conf));
	if (!conf)
		return NULL;

	nwif_iface_conf_init(&conf->iface, NWIF_ETHER_IFACE_TYPE);

	return conf;
}

#if 0

////////////////////////////////////////////////////////////////////////////////

struct nwif_ether {
	struct nwif_ether_conf  conf;
	struct nwif_iface_state state;
};

static int
nwif_ether_build_apply_request(struct nwif_ether *eif,
                               struct nlmsghdr   *msg,
                               struct nlink_sock *sock)
{
	int                      ret;
	const char              *name;
	const struct ether_addr *addr;
	uint32_t                 mtu;
	uint8_t                  oper;

	nlink_iface_setup_msg(msg,
	                      sock,
	                      ARPHRD_ETHER,
	                      nwif_iface_state_get_id(&eif->state));

	name = nwif_ether_conf_get_name(&eif->conf);
	if (name) {
		ret = nlink_iface_setup_msg_name(msg, name, strlen(name));
		if (ret)
			return ret;
	}

	addr = nwif_ether_conf_get_addr(&eif->conf);
	if (addr) {
		ret = nlink_iface_setup_msg_addr(msg, addr);
		if (ret)
			return ret;
	}

	ret = nwif_ether_conf_get_mtu(&eif->conf, &mtu);
	if (!ret) {
		ret = nlink_iface_setup_msg_mtu(msg, mtu);
		if (ret)
			return ret;
	}
	else if (ret != -ENODATA)
		return ret;

	ret = nwif_ether_conf_get_oper_state(&eif->conf, &oper);
	if (!ret) {
		ret = nlink_iface_setup_msg_oper_state(msg, oper);
		if (ret)
			return ret;
	}
	else if (ret != -ENODATA)
		return ret;

	return 0;
}

static int
nwif_ether_parse_apply_reply(const struct nlmsghdr *msg)
{
	int err;

	err = nlink_parse_msg_head(msg);

	return (err == -ENODATA) ? 0 : err;
}

struct nwif_ether *
nwif_ether_create_from_conf(const struct nwif_iface_conf *conf)
{
	struct nwif_ether            *eif;
	const struct nwif_ether_conf *econf = (struct nwif_ether_conf *)conf;
	int                           err;

	eif = malloc(sizeof(*eif));
	if (!eif) {
		errno = ENOMEM;
		return NULL;
	}

	eif->conf = *econf;

	err = nwif_iface_probe_id(conf->sys_path);
	if (err < 0)
		goto free;

	nwif_iface_state_init(&eif->state, err);

	return eif;

free:
	free(eif);

	errno = -err;
	return NULL;
}

////////////////////////////////////////////////////////////////////////////////

static const struct nwif_ether_conf eth0 = {
	.super = {
		.attr_mask  = NWIF_NAME_ATTR | NWIF_MTU_ATTR | NWIF_OPER_STATE_ATTR,
		.sys_path   = "platform/10013400.virtio_mmio/virtio0",
		.type       = NWIF_ETHER_IFACE_TYPE,
	},
	.name               = "eth0ext",
	.mtu                = 1500,
	.oper_state         = IF_OPER_DOWN,
};

static const struct nwif_ether_conf eth1 = {
	.super = {
		.attr_mask  = NWIF_NAME_ATTR | NWIF_MTU_ATTR | NWIF_OPER_STATE_ATTR,
		.sys_path   = "platform/10013600.virtio_mmio/virtio1",
		.type       = NWIF_ETHER_IFACE_TYPE,
	},
	.name               = "eth1int",
	.mtu                = 4000,
	.oper_state         = IF_OPER_DOWN,
};


struct nwif_iface_conf_store {
	struct nwif_iface_conf * ifaces[2];
};

static const struct nwif_iface_conf_store iface_conf_store = {
	.ifaces = {
		(struct nwif_iface_conf *)&eth0,
		(struct nwif_iface_conf *)&eth1
	}
};

unsigned int
nwif_iface_conf_store_count(const struct nwif_iface_conf_store *store)
{
	return 2;
}

struct nwif_iface_conf_iter {
	unsigned int curr;
};

struct nwif_iface_conf *
nwif_iface_conf_iter_begin(struct nwif_iface_conf_iter        *iter,
                           const struct nwif_iface_conf_store *store)
{
	iter->curr = 1;

	return store->ifaces[0];
}

struct nwif_iface_conf *
nwif_iface_conf_iter_next(struct nwif_iface_conf_iter        *iter,
                          const struct nwif_iface_conf_store *store)
{
	if (iter->curr >= 2)
		return NULL;

	return store->ifaces[iter->curr++];
}

///////////////////////////////////////////////////////////////////////////////

#include <utils/thread.h>

static int
nwif_send_msg_sync(const struct nlink_sock *sock, const struct nlmsghdr *msg)
{
	nwif_assert(sock);
	nwif_assert(msg);

	int ret;

	do {
		ret = nlink_send_msg(sock, msg);
		if (ret == -EAGAIN)
			uthr_yield();
	} while ((ret == -EAGAIN) || (ret == -EINTR));

	return ret;
}

static ssize_t
nwif_recv_msg_sync(const struct nlink_sock *sock, struct nlmsghdr *msg)
{
	nwif_assert(sock);
	nwif_assert(msg);

	ssize_t ret;

	do {
		ret = nlink_recv_msg(sock, msg);

		if (ret == -EAGAIN)
			uthr_yield();
	} while ((ret == -EAGAIN) || (ret == -EINTR));

	nwif_assert(ret);

	return ret;
}

struct nwif_ether_xfer {
	struct nwif_ether *eif;
	uint32_t           seqno;
};

static int
nwif_iface_apply_conf(const struct nwif_iface_conf_store *store,
                      struct nlink_sock                  *sock,
                      struct nlmsghdr                    *msg)
{
	struct nwif_iface_conf_iter  iter;
	struct nwif_iface_conf      *conf;
	int                          ret;
	unsigned int                 cnt;
	struct nwif_ether_xfer      *xfers;
	unsigned int                 x = 0;

	cnt = nwif_iface_conf_store_count(store);
	if (!cnt)
		return -ENOENT;

	xfers = malloc(cnt * sizeof(*xfers));
	if (!xfers)
		return -errno;

	for (conf = nwif_iface_conf_iter_begin(&iter, store);
	     conf;
	     conf = nwif_iface_conf_iter_next(&iter, store)) {
		struct nwif_ether *eif;

		eif = nwif_ether_create_from_conf(conf);
		if (!eif) {
			printf("failed to create ether interface: %s\n",
			       strerror(errno));
			continue;
		}

#warning register iface to repository !!

		ret = nwif_ether_build_apply_request(eif, msg, sock);
		if (ret) {
			printf("failed to build ether interface config request: %s\n",
			       strerror(-ret));
			free(eif);
			continue;
		}

		ret = nwif_send_msg_sync(sock, msg);
		if (ret) {
			printf("failed to transmit ether interface config request: %s\n",
			       strerror(-ret));
			free(eif);
			uthr_yield();
			continue;
		}

		xfers[x].eif = eif;
		xfers[x].seqno = msg->nlmsg_seq;
		x++;
	}

	if (!x) {
		ret = -ENODEV;
		goto free;
	}

	cnt = x;

	do {
		unsigned int c;

		ret = nwif_recv_msg_sync(sock, msg);
		if (ret < 0) {
			printf("failed to fetch ether interface config reply: %s\n",
			       strerror(-ret));
			uthr_yield();
			continue;
		}

		for (c = 0; c < cnt; c++) {
			if (xfers[c].eif && (xfers[c].seqno == msg->nlmsg_seq))
				break;
		}
		if (c == cnt) {
			printf("unexpected ether interface config reply\n");
			continue;
		}

		ret = nwif_ether_parse_apply_reply(msg);
		if (ret)
			printf("ether interface config reply parsing failed: %s\n",
			       strerror(-ret));

		xfers[c].eif = NULL;
	} while (--x);

free:
	free(xfers);

#warning destroy iface repository !!
	return ret;
}

int
main(int argc, char * const argv[])
{
	int                           ret;
	struct nlink_sock             sock;
	struct nlmsghdr              *msg;

	ret = nlink_open_sock(&sock, NETLINK_ROUTE, 0);
	if (ret)
		goto out;

	msg = nlink_alloc_msg();
	if (!msg) {
		ret = -ENOMEM;
		goto close;
	}

	ret = nwif_iface_apply_conf(&iface_conf_store, &sock, msg);

	nlink_free_msg(msg);

close:
	nlink_close_sock(&sock);

out:
	if (ret) {
		printf("error: %s\n", strerror(-ret));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
#endif
