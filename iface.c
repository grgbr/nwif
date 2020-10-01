#include "iface_priv.h"
#include "conf_priv.h"
#include <utils/net.h>
#include <utils/string.h>
#include <glob.h>
#include <linux/if.h>
#include <linux/rtnetlink.h>

#define NWIF_IFACE_CONF_BASENAME       "iface"
#define NWIF_SYSNETDEV_IFINDEX_PATTERN "net/*/ifindex"

int
nwif_iface_probe_sysid(const char *syspath)
{
	nwif_assert(syspath);
	nwif_assert(unet_check_iface_syspath(syspath) > 0);

	char   *pat;
	glob_t  res;
	FILE   *file;
	int     ret;

	if (asprintf(&pat,
	             UNET_IFACE_SYSPATH_PREFIX
	             "/%s/"
	             NWIF_SYSNETDEV_IFINDEX_PATTERN,
	             syspath) < 0)
		return -errno;

	ret = glob(pat, GLOB_ERR | GLOB_NOSORT, NULL, &res);
	switch (ret) {
	case 0:
		break;

	case GLOB_NOSPACE:
		ret = -ENOMEM;
		goto free;

	case GLOB_ABORTED:
		ret = -errno;
		goto free;

	case GLOB_NOMATCH:
		ret = -ENOENT;
		goto free;

	default:
		nwif_assert(0);
	}

	file = fopen(res.gl_pathv[0], "r");
	if (!file) {
		ret = -errno;
		goto free;
	}

	if (fscanf(file, "%d\n", &ret) == 1)
		ret = (ret > 0) ? ret : -ENODEV;
	else
		ret = -ENODEV;

	fclose(file);

free:
	globfree(&res);
	free(pat);

	return ret;
}

/******************************************************************************
 * Interface configuration table handling
 ******************************************************************************/

#if defined(CONFIG_NWIF_ETHER)

extern const struct nwif_iface_conf_impl nwif_ether_conf_impl;
#define NWIF_ETHER_CONF_IMPL (&nwif_ether_conf_impl)

#else  /* !defined(CONFIG_NWIF_ETHER) */

#define NWIF_ETHER_CONF_IMPL (NULL)

#endif /* defined(CONFIG_NWIF_ETHER) */

static const struct nwif_iface_conf_impl * const
nwif_iface_conf_impl_table[NWIF_IFACE_TYPE_NR] = {
	[NWIF_ETHER_IFACE_TYPE] = NWIF_ETHER_CONF_IMPL
};

static const struct nwif_iface_conf_impl *
nwif_iface_conf_get_impl(const struct nwif_iface_conf_data *data)
{
	nwif_iface_conf_assert_data(data);

	const struct nwif_iface_conf_impl *impl;

	impl = nwif_iface_conf_impl_table[data->type];
	if (!impl) {
		errno = ENOTSUP;
		return NULL;
	}

	nwif_iface_conf_assert_impl(impl);

	return impl;
}

static int
nwif_iface_conf_open_data(struct kvs_table       *table,
                          const struct kvs_depot *depot,
                          const struct kvs_xact  *xact,
                          mode_t                  mode)
{
	return kvs_autorec_open(kvs_table_get_data_store(table),
	                        depot,
	                        xact,
	                        NWIF_IFACE_CONF_BASENAME ".dat",
	                        mode);
}

static int
nwif_iface_conf_close_data(const struct kvs_table *table)
{
	return kvs_autorec_close(kvs_table_get_data_store(table));
}

static int
nwif_iface_conf_bind_name_indx(const struct kvs_chunk *pkey __unused,
                               const struct kvs_chunk *item,
                               struct kvs_chunk       *skey)
{
	nwif_assert(pkey->size);
	nwif_assert(pkey->data);
	nwif_assert(item->size);
	nwif_assert(item->data);
	nwif_assert(skey);

	const struct nwif_iface_conf_data *data;

	data = (struct nwif_iface_conf_data *)item->data;

	nwif_assert(item->size > sizeof(*data));
	nwif_iface_conf_assert_data(data);

	if (!nwif_iface_conf_data_has_attr(data, NWIF_NAME_ATTR)) {
		skey->size = 0;
		return 0;
	}

	nwif_assert(unet_check_iface_name(data->name) > 0);

	skey->data = data->name;
	skey->size = strlen(data->name);

	return 0;
}

static int
nwif_iface_conf_open_name_indx(struct kvs_table       *table,
                               const struct kvs_depot *depot,
                               const struct kvs_xact  *xact,
                               mode_t                  mode)
{
	struct kvs_store *indx;

	indx = kvs_table_get_indx_store(table, NWIF_IFACE_CONF_NAME_IID);

	return kvs_open_indx(indx,
	                     &table->data,
	                     depot,
	                     xact,
	                     NWIF_IFACE_CONF_BASENAME ".idx",
	                     "name",
	                     mode,
	                     nwif_iface_conf_bind_name_indx);
}

static int
nwif_iface_conf_close_name_indx(const struct kvs_table *table)
{
	return kvs_close_indx(
		kvs_table_get_indx_store(table, NWIF_IFACE_CONF_NAME_IID));
}

static int
nwif_iface_conf_bind_syspath_indx(const struct kvs_chunk *pkey __unused,
                                  const struct kvs_chunk *item,
                                  struct kvs_chunk       *skey)
{
	nwif_assert(pkey->size);
	nwif_assert(pkey->data);
	nwif_assert(item->size);
	nwif_assert(item->data);
	nwif_assert(skey);

	const struct nwif_iface_conf_data *data;
	const struct nwif_iface_conf_impl *impl;

	data = (struct nwif_iface_conf_data *)item->data;

	nwif_assert(item->size > sizeof(*data));
	if (!nwif_iface_conf_data_has_attr(data, NWIF_SYSPATH_ATTR)) {
		skey->size = 0;
		return 0;
	}

	impl = nwif_iface_conf_get_impl(data);
	if (!impl)
		return -errno;

	return impl->bind_syspath(item, skey);
}

static int
nwif_iface_conf_open_syspath_indx(struct kvs_table       *table,
                                  const struct kvs_depot *depot,
                                  const struct kvs_xact  *xact,
                                  mode_t                  mode)
{
	struct kvs_store *indx;
	
	indx = kvs_table_get_indx_store(table, NWIF_IFACE_CONF_SYSPATH_IID);

	return kvs_open_indx(indx,
	                     &table->data,
	                     depot,
	                     xact,
	                     NWIF_IFACE_CONF_BASENAME ".idx",
	                     "syspath",
	                     mode,
	                     nwif_iface_conf_bind_syspath_indx);
}

static int
nwif_iface_conf_close_syspath_indx(const struct kvs_table *table)
{
	return kvs_close_indx(
		kvs_table_get_indx_store(table, NWIF_IFACE_CONF_SYSPATH_IID));
}

static int
nwif_iface_conf_bind_hwaddr_indx(const struct kvs_chunk *pkey,
                                 const struct kvs_chunk *item,
                                 struct kvs_chunk       *skey)
{
	nwif_assert(pkey->size);
	nwif_assert(pkey->data);
	nwif_assert(item->size);
	nwif_assert(item->data);
	nwif_assert(skey);

	const struct nwif_iface_conf_data *data;
	const struct nwif_iface_conf_impl *impl;

	data = (struct nwif_iface_conf_data *)item->data;

	nwif_assert(item->size > sizeof(*data));
	if (!nwif_iface_conf_data_has_attr(data, NWIF_HWADDR_ATTR)) {
		skey->size = 0;
		return 0;
	}

	impl = nwif_iface_conf_get_impl(data);
	if (!impl)
		return -errno;

	return impl->bind_hwaddr(item, skey);
}

static int
nwif_iface_conf_open_hwaddr_indx(struct kvs_table       *table,
                                 const struct kvs_depot *depot,
                                 const struct kvs_xact  *xact,
                                 mode_t                  mode)
{
	struct kvs_store *indx;
	
	indx = kvs_table_get_indx_store(table, NWIF_IFACE_CONF_HWADDR_IID);

	return kvs_open_indx(indx,
	                     &table->data,
	                     depot,
	                     xact,
	                     NWIF_IFACE_CONF_BASENAME ".idx",
	                     "hwaddr",
	                     mode,
	                     nwif_iface_conf_bind_hwaddr_indx);
}

static int
nwif_iface_conf_close_hwaddr_indx(const struct kvs_table *table)
{
	return kvs_close_indx(
		kvs_table_get_indx_store(table, NWIF_IFACE_CONF_HWADDR_IID));
}

const struct kvs_table_desc nwif_iface_conf_desc = {
	.data_ops = {
		.open  = nwif_iface_conf_open_data,
		.close = nwif_iface_conf_close_data
	},
	.indx_nr  = NWIF_IFACE_CONF_IID_NR,
	.indx_ops = {
		[NWIF_IFACE_CONF_NAME_IID] = {
			.open  = nwif_iface_conf_open_name_indx,
			.close = nwif_iface_conf_close_name_indx
		},
		[NWIF_IFACE_CONF_SYSPATH_IID] = {
			.open  = nwif_iface_conf_open_syspath_indx,
			.close = nwif_iface_conf_close_syspath_indx
		},
		[NWIF_IFACE_CONF_HWADDR_IID] = {
			.open  = nwif_iface_conf_open_hwaddr_indx,
			.close = nwif_iface_conf_close_hwaddr_indx
		}
	}
};

static int
nwif_iface_conf_get_byid(const struct kvs_table *table,
                         const struct kvs_xact  *xact,
                         uint64_t                id,
                         struct kvs_chunk       *item)
{
	return kvs_autorec_get_byid(kvs_table_get_data_store(table),
	                            xact,
	                            id,
	                            item);
}

static int
nwif_iface_conf_get_byname(const struct kvs_table *table,
                           const struct kvs_xact  *xact,
                           const char             *name,
                           size_t                  len,
                           uint64_t               *id,
                           struct kvs_chunk       *item)
{
	nwif_assert(unet_check_iface_name(name) == (ssize_t)len);

	const struct kvs_chunk  field = {
		.size = len,
		.data = name
	};

	return kvs_autorec_get_byfield(
		kvs_table_get_indx_store(table, NWIF_IFACE_CONF_NAME_IID),
		xact,
		&field,
		id,
		item);
}

static int
nwif_iface_conf_get_bysyspath(const struct kvs_table *table,
                              const struct kvs_xact  *xact,
                              const char             *syspath,
                              size_t                  len,
                              uint64_t               *id,
                              struct kvs_chunk       *item)
{
	nwif_assert(unet_check_iface_syspath(syspath) == (ssize_t)len);

	const struct kvs_chunk  field = {
		.size = len,
		.data = syspath
	};

	return kvs_autorec_get_byfield(
		kvs_table_get_indx_store(table, NWIF_IFACE_CONF_SYSPATH_IID),
		xact,
		&field,
		id,
		item);
}

static int
nwif_iface_conf_save_byid(const struct kvs_table            *table,
                          const struct kvs_xact             *xact,
                          uint64_t                          *id,
                          const struct nwif_iface_conf_data *data)
{
	nwif_assert(id);

	int                                err;
	struct kvs_chunk                   item;
	const struct nwif_iface_conf_impl *impl;

	impl = nwif_iface_conf_get_impl(data);
	if (!impl)
		return -errno;

	err = impl->check_data(*id, data);
	if (err < 0)
		return err;

	item.data = data;
	item.size = impl->data_size;
	if (!kvs_autorec_id_isok(*id))
		err = kvs_autorec_add(kvs_table_get_data_store(table),
		                      xact,
		                      id,
		                      &item);
	else
		err = kvs_autorec_update(kvs_table_get_data_store(table),
		                         xact,
		                         *id,
		                         &item);

	if (err)
		return err;

	nwif_assert(kvs_autorec_id_isok(*id));

	return 0;
}

int
nwif_iface_conf_del_byname(const struct kvs_table *table,
                           const struct kvs_xact  *xact,
                           const char             *name,
                           size_t                  len)
{
	nwif_assert(unet_check_iface_name(name) == (ssize_t)len);

	const struct kvs_chunk field = { .size = len, .data = name };

	return kvs_autorec_del_byfield(
		kvs_table_get_indx_store(table, NWIF_IFACE_CONF_NAME_IID),
		xact,
		&field);
}

static const struct nwif_iface_conf_impl *
nwif_iface_conf_check_data(uint64_t                           id,
                           const struct nwif_iface_conf_data *data,
                           size_t                             size)
{
	nwif_assert(kvs_autorec_id_isok(id));
	nwif_assert(data);
	nwif_assert(size > sizeof(*data));

	const struct nwif_iface_conf_impl *impl;

	impl = nwif_iface_conf_get_impl(data);
	if (!impl)
		return NULL;

	nwif_assert(size == impl->data_size);
	nwif_assert(!impl->check_data(id, data));

	return impl;
}

struct nwif_iface_conf *
nwif_iface_conf_create_from_rec(const struct kvs_table *table,
                                uint64_t                id,
                                const struct kvs_chunk *item)
{
	kvs_table_assert(table);
	nwif_assert(kvs_autorec_id_isok(id));
	nwif_assert(item);

	const struct nwif_iface_conf_impl *impl;
	struct nwif_iface_conf            *conf;

	impl = nwif_iface_conf_check_data(id, item->data, item->size);
	if (!impl) {
		conf->state = NWIF_IFACE_CONF_FAIL_STATE;
		return NULL;
	}

	conf = nwif_iface_conf_alloc(impl->data_size);
	if (!conf)
		return NULL;

	conf->state = NWIF_IFACE_CONF_CLEAN_STATE;
	conf->id = id;
	conf->table = table;
	memcpy(conf->data, item->data, impl->data_size);

	return conf;
}

struct nwif_iface_conf *
nwif_iface_conf_create_byid(const struct kvs_table *table,
                            const struct kvs_xact  *xact,
                            uint64_t                id)
{
	struct kvs_chunk item;
	int              err;

	err = nwif_iface_conf_get_byid(table, xact, id, &item);
	if (err) {
		errno = -err;
		return NULL;
	}

	return nwif_iface_conf_create_from_rec(table, id, &item);
}

struct nwif_iface_conf *
nwif_iface_conf_create_byname(const struct kvs_table *table,
                              const struct kvs_xact  *xact,
                              const char             *name,
                              size_t                  len)
{
	uint64_t         id;
	struct kvs_chunk item;
	int              err;

	err = nwif_iface_conf_get_byname(table, xact, name, len, &id, &item);
	if (err) {
		errno = -err;
		return NULL;
	}

	return nwif_iface_conf_create_from_rec(table, id, &item);
}

struct nwif_iface_conf *
nwif_iface_conf_create_bysyspath(const struct kvs_table *table,
                                 const struct kvs_xact  *xact,
                                 const char             *name,
                                 size_t                  len)
{
	uint64_t         id;
	struct kvs_chunk item;
	int              err;

	err = nwif_iface_conf_get_bysyspath(table, xact, name, len, &id, &item);
	if (err) {
		errno = -err;
		return NULL;
	}

	return nwif_iface_conf_create_from_rec(table, id, &item);
}

/******************************************************************************
 * Interface configuration handling
 ******************************************************************************/

const char *
nwif_iface_conf_get_name(const struct nwif_iface_conf *conf)
{
	nwif_iface_conf_assert(conf);
	nwif_assert(conf->state != NWIF_IFACE_CONF_EMPTY_STATE);

	if (!nwif_iface_conf_has_attr(conf, NWIF_NAME_ATTR))
		return NULL;

	return conf->data[0].name;
}

void
nwif_iface_conf_set_name(struct nwif_iface_conf *conf,
                         const char             *name,
                         size_t                  len)
{
	nwif_iface_conf_assert(conf);
	nwif_assert(unet_check_iface_name(name) == (ssize_t)len);

	if (nwif_iface_conf_has_attr(conf, NWIF_NAME_ATTR) &&
	    !strncmp(conf->data[0].name, name, sizeof(conf->data[0].name)))
		return;

	memcpy(conf->data[0].name, name, len);
	conf->data[0].name[len] = '\0';

	nwif_iface_conf_set_attr(conf, NWIF_NAME_ATTR);
}

void
nwif_iface_conf_clear_name(struct nwif_iface_conf *conf)
{
	nwif_iface_conf_assert(conf);
	nwif_assert(conf->state != NWIF_IFACE_CONF_EMPTY_STATE);

	nwif_iface_conf_clear_attr(conf, NWIF_NAME_ATTR);
}

void
nwif_iface_conf_get_admin_state(const struct nwif_iface_conf *conf,
                                uint8_t                      *state)
{
	nwif_iface_conf_assert(conf);
	nwif_assert(conf->state != NWIF_IFACE_CONF_EMPTY_STATE);
	nwif_assert(state);

	if (nwif_iface_conf_has_attr(conf, NWIF_ADMIN_STATE_ATTR))
		*state = conf->data[0].admin_state;
	else
		*state = IF_OPER_DOWN;
}

void
nwif_iface_conf_set_admin_state(struct nwif_iface_conf *conf, uint8_t state)
{
	nwif_iface_conf_assert(conf);
	nwif_assert(unet_iface_admin_state_isok(state));

	if (nwif_iface_conf_has_attr(conf, NWIF_ADMIN_STATE_ATTR) &&
	    (conf->data[0].admin_state == state))
		return;

	conf->data[0].admin_state = state;

	nwif_iface_conf_set_attr(conf, NWIF_ADMIN_STATE_ATTR);
}

void
nwif_iface_conf_clear_admin_state(struct nwif_iface_conf *conf)
{
	nwif_iface_conf_assert(conf);
	nwif_assert(conf->state != NWIF_IFACE_CONF_EMPTY_STATE);

	nwif_iface_conf_clear_attr(conf, NWIF_ADMIN_STATE_ATTR);
}

int
nwif_iface_conf_get_mtu(const struct nwif_iface_conf *conf, uint32_t *mtu)
{
	nwif_iface_conf_assert(conf);
	nwif_assert(conf->state != NWIF_IFACE_CONF_EMPTY_STATE);
	nwif_assert(mtu);

	if (!nwif_iface_conf_has_attr(conf, NWIF_MTU_ATTR))
		return -ENODATA;

	*mtu = conf->data[0].mtu;

	return 0;
}

void
nwif_iface_conf_set_mtu(struct nwif_iface_conf *conf, uint32_t mtu)
{
	nwif_iface_conf_assert(conf);
	nwif_assert(unet_iface_mtu_isok(mtu));

	if (nwif_iface_conf_has_attr(conf, NWIF_MTU_ATTR) &&
	    (conf->data[0].mtu == mtu))
		return;

	conf->data[0].mtu = mtu;

	nwif_iface_conf_set_attr(conf, NWIF_MTU_ATTR);
}

void
nwif_iface_conf_clear_mtu(struct nwif_iface_conf *conf)
{
	nwif_iface_conf_assert(conf);
	nwif_assert(conf->state != NWIF_IFACE_CONF_EMPTY_STATE);

	nwif_iface_conf_clear_attr(conf, NWIF_MTU_ATTR);
}

int
nwif_iface_conf_reload(struct nwif_iface_conf *conf,
                       const struct kvs_xact  *xact)
{
	nwif_assert(conf->state != NWIF_IFACE_CONF_EMPTY_STATE);

	struct kvs_chunk                   item;
	const struct nwif_iface_conf_impl *impl;
	int                                err;

	err = nwif_iface_conf_get_byid(conf->table, xact, conf->id, &item);
	if (err)
		return err;

	impl = nwif_iface_conf_check_data(conf->id, item.data, item.size);
	if (!impl) {
		conf->state = NWIF_IFACE_CONF_FAIL_STATE;
		return -errno;
	}

	nwif_assert(conf->data[0].type ==
	            ((struct nwif_iface_conf_data *)item.data)->type);

	conf->state = NWIF_IFACE_CONF_CLEAN_STATE;
	memcpy(conf->data, item.data, impl->data_size);

	return 0;
}

int
nwif_iface_conf_del(struct nwif_iface_conf *conf, const struct kvs_xact *xact)
{
	nwif_assert(conf);

	int ret;

	switch (conf->state) {
	case NWIF_IFACE_CONF_CLEAN_STATE:
	case NWIF_IFACE_CONF_DIRTY_STATE:
		break;

	case NWIF_IFACE_CONF_EMPTY_STATE:
	case NWIF_IFACE_CONF_FAIL_STATE:
	default:
		nwif_assert(0);
	}

	nwif_iface_conf_assert_data(conf->data);

	ret = nwif_iface_conf_del_byid(conf->table, xact, conf->id);

	conf->state = NWIF_IFACE_CONF_FAIL_STATE;
	conf->id = 0;

	return ret;
}

int
nwif_iface_conf_save(struct nwif_iface_conf *conf, const struct kvs_xact *xact)
{
	nwif_assert(conf);

	int err;

	switch (conf->state) {
	case NWIF_IFACE_CONF_CLEAN_STATE:
		return 0;

	case NWIF_IFACE_CONF_DIRTY_STATE:
		break;

	case NWIF_IFACE_CONF_EMPTY_STATE:
	case NWIF_IFACE_CONF_FAIL_STATE:
	default:
		nwif_assert(0);
	}

	err = nwif_iface_conf_save_byid(conf->table,
	                                xact,
	                                &conf->id,
	                                conf->data);

	conf->state = !err ? NWIF_IFACE_CONF_CLEAN_STATE :
	                     NWIF_IFACE_CONF_FAIL_STATE;

	return err;
}

void
nwif_iface_conf_init(struct nwif_iface_conf *conf,
                     enum nwif_iface_type    type,
                     const struct kvs_table *table)
{
	nwif_assert(conf);
	nwif_assert(type >= 0);
	nwif_assert(type < NWIF_IFACE_TYPE_NR);
	kvs_table_assert(table);

	conf->state = NWIF_IFACE_CONF_EMPTY_STATE;
	conf->id = 0;
	conf->table = table;
	conf->data[0].type = type;
	conf->data[0].attr_mask = 0U;
}

/******************************************************************************
 * Interface state handling
 ******************************************************************************/

extern const struct nwif_iface_state_impl nwif_loopback_state_impl;

#if defined(CONFIG_NWIF_ETHER)

extern const struct nwif_iface_state_impl nwif_ether_state_impl;
#define NWIF_ETHER_STATE_IMPL (&nwif_ether_state_impl)

#else  /* !defined(CONFIG_NWIF_ETHER) */

#define NWIF_ETHER_STATE_IMPL (NULL)

#endif /* defined(CONFIG_NWIF_ETHER) */

static const struct nwif_iface_state_impl * const
nwif_iface_state_impl_table[NWIF_IFACE_TYPE_NR] = {
	[NWIF_LOOPBACK_IFACE_TYPE] = &nwif_loopback_state_impl,
	[NWIF_ETHER_IFACE_TYPE]    = NWIF_ETHER_STATE_IMPL
};

static int
nwif_iface_state_parse_ack(int status, const struct nlmsghdr *msg, void *data)
{
	nwif_assert(msg);
	nwif_state_assert_sock((struct nwif_state_sock *)data);

#warning implement iface content update ??

	return (status == -ENODATA) ? 0 : status;
}

int
nwif_iface_state_start_apply(struct nwif_iface_state      *iface,
                             const struct nwif_iface_conf *conf)
{
	nwif_iface_state_assert(iface);
	nwif_iface_conf_assert(conf);

	const struct nwif_iface_state_impl *impl;
	struct nwif_state_sock             *sock = iface->sock;
	struct nlmsghdr                    *msg = sock->msg;
	int                                 err;
	const char                         *name;
	uint8_t                             admin;
	uint32_t                            mtu;
	bool                                send = false;

	impl = nwif_iface_state_impl_table[iface->type];
	nlink_iface_setup_new(msg, &sock->nlink, impl->arp_type, iface->sysid);

	name = nwif_iface_conf_get_name(conf);
	if (name && strcmp(name, iface->name)) {
		err = nlink_iface_setup_msg_name(msg, name, strlen(name));
		if (err)
			return err;
		send = true;
	}

	nwif_iface_conf_get_admin_state(conf, &admin);
	if (admin != iface->admin_state) {
		err = nlink_iface_setup_msg_admin_state(msg, admin);
		if (err)
			return err;
		send = true;
	}

	err = nwif_iface_conf_get_mtu(conf, &mtu);
	nwif_assert(!err || (err == -ENODATA));
	if (!err && (mtu != iface->mtu)) {
		err = nlink_iface_setup_msg_mtu(msg, mtu);
		if (err)
			return err;
		send = true;
	}

	err = impl->apply_conf(iface, msg, conf);
	if (err) {
		if (err != -ECANCELED)
			return err;
	}
	else
		send = true;

	if (!send)
		return 0;

	return nwif_state_start_xfer(sock, msg, nwif_iface_state_parse_ack);
}

static int
nwif_iface_state_fill(struct nwif_iface_state            *iface,
                      const struct nwif_iface_state_impl *impl,
                      const struct nlink_iface           *attrs)
{
	memcpy(iface->name, attrs->name, attrs->name_len);
	iface->name[attrs->name_len] = '\0';
	iface->admin_state = attrs->admin_state;
	iface->oper_state = attrs->oper_state;
	iface->carrier_state = attrs->carrier_state;
	iface->mtu = attrs->mtu;

	return impl->fill_attrs(iface, attrs);
}

int
nwif_iface_state_update(struct nwif_iface_state  *iface,
                        const struct nlink_iface *attrs)
{
	nwif_iface_state_assert(iface);
	nwif_iface_state_assert_attrs(attrs);
	nwif_assert(iface->sysid == attrs->index);
	nwif_assert(iface->type == attrs->type);
	nwif_assert(iface->type < array_nr(nwif_iface_state_impl_table));

	const struct nwif_iface_state_impl *impl;

	impl = nwif_iface_state_impl_table[iface->type];
	nwif_assert(impl->probe_type(attrs));

	return nwif_iface_state_fill(iface, impl, attrs);
}

struct nwif_iface_state *
nwif_iface_state_create(struct nwif_state_sock   *sock,
                        const struct nlink_iface *attrs)
{
	nwif_state_assert_sock(sock);
	nwif_iface_state_assert_attrs(attrs);

	int                                 err;
	unsigned int                        i;
	const struct nwif_iface_state_impl *impl;
	struct nwif_iface_state            *iface;

	for (i = 0; i < array_nr(nwif_iface_state_impl_table); i++) {
		impl = nwif_iface_state_impl_table[i];

		if (impl &&
		    (impl->arp_type == attrs->type) &&
		    impl->probe_type(attrs))
			break;
	}

	if (i == array_nr(nwif_iface_state_impl_table)) {
		errno = ENOTSUP;
		return NULL;
	}

	iface = malloc(impl->size);
	if (!iface)
		return NULL;

	nwif_iface_state_init(iface, attrs->index, i, sock);
	err = nwif_iface_state_fill(iface, impl, attrs);
	if (err)
		goto free;

	return iface;

free:
	free(iface);

	errno = -err;
	return NULL;
}

struct nwif_iface_state *
nwif_iface_state_create_from_msg(struct nwif_state_sock *sock,
                                 const struct nlmsghdr  *msg)
{
	nwif_assert(msg);
	nwif_assert(msg->nlmsg_type == RTM_NEWLINK);

	struct nlink_iface attrs;
	int                err;

	err = nwif_iface_state_parse_msg(msg, &attrs);
	if (err) {
		errno = -err;
		return NULL;
	}

	return nwif_iface_state_create(sock, &attrs);
}

/******************************************************************************
 * Interface cache handling
 ******************************************************************************/

static int
nwif_iface_cache_compare_sysid(const struct pavl_node *node,
                               const void             *key,
                               const void             *data __unused)
{
	nwif_assert(node);
	nwif_assert((int)key > 1);

	const struct nwif_iface *iface = containerof(node,
	                                             struct nwif_iface,
	                                             sysid_node);

	return nwif_iface_state_get_id(iface->state) - (int)key;
}

static void
nwif_iface_cache_release(struct pavl_node *node, void *data __unused)
{
	nwif_assert(node);
	
	nwif_iface_destroy(containerof(node, struct nwif_iface, sysid_node));
}

void
nwif_iface_cache_init(struct nwif_iface_cache *cache)
{
	nwif_assert(cache);

	pavl_init_tree(&cache->sysid_avl,
	               nwif_iface_cache_compare_sysid,
	               nwif_iface_cache_release,
	               NULL);
}

/******************************************************************************
 * Top-level interface handling
 ******************************************************************************/

static ssize_t
nwif_iface_probe_syspath(const char *name, char **syspath)
{
	nwif_assert(unet_check_iface_name(name) > 0);
	nwif_assert(syspath);

	char    *class;
	ssize_t  len;

	if (asprintf(&class, UNET_IFACE_CLASS_PREFIX "/%s", name) < 0)
		return -errno;

	len = unet_resolve_iface_syspath(class, syspath);

	free(class);

	return len;
}

int
nwif_iface_load(struct nwif_iface     *iface,
                const struct kvs_repo *conf,
                const struct kvs_xact *xact)
{
	nwif_assert(iface);
	nwif_assert(iface->state);
	nwif_assert(conf);
	nwif_assert(xact);

	if (!iface->conf) {
		char *syspath;
		int   ret;

		ret = nwif_iface_probe_syspath(
				nwif_iface_state_get_name(iface->state),
				&syspath);
		if (ret < 0)
			return ret;

		iface->conf =
			nwif_iface_conf_create_bysyspath(
				nwif_conf_get_iface_table(conf),
				xact,
				syspath,
				ret);

		ret = -errno;
		free(syspath);

		return iface->conf ? 0 : ret;
	}

	return nwif_iface_conf_reload(iface->conf, xact);
}

struct nwif_iface *
nwif_iface_create(struct nwif_state_sock *sock, const struct nlink_iface *attrs)
{
	struct nwif_iface *iface;

	iface = malloc(sizeof(*iface));
	if (!iface)
		return NULL;

	iface->state = nwif_iface_state_create(sock, attrs);
	if (!iface->state) {
		int err = errno;

		free(iface);

		errno = err;
		return NULL;
	}

	iface->conf = NULL;

	return iface;
}

void
nwif_iface_destroy(struct nwif_iface *iface)
{
	nwif_assert(iface);
	nwif_assert(iface->state);

	if (iface->conf)
		nwif_iface_conf_destroy(iface->conf);

	nwif_iface_state_destroy(iface->state);

	free(iface);
}
