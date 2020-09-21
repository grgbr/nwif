#include "iface_priv.h"
#include <utils/string.h>
#include <glob.h>
#include <linux/if.h>

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
	             UNET_IFACE_SYSPATH_PREFIX "/%s/" NWIF_SYSNETDEV_IFINDEX_PATTERN,
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
 * Interface attribute related helpers
 ******************************************************************************/

bool
nwif_iface_oper_state_isok(uint8_t oper_state)
{
	switch (oper_state) {
	case IF_OPER_UP:
	case IF_OPER_DOWN:
		return true;

	default:
		return false;
	}
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
nwif_iface_conf_get_oper_state(const struct nwif_iface_conf *conf,
                               uint8_t                      *oper_state)
{
	nwif_iface_conf_assert(conf);
	nwif_assert(conf->state != NWIF_IFACE_CONF_EMPTY_STATE);
	nwif_assert(oper_state);

	if (nwif_iface_conf_has_attr(conf, NWIF_OPER_STATE_ATTR))
		*oper_state = conf->data[0].oper_state;
	else
		*oper_state = IF_OPER_DOWN;
}

void
nwif_iface_conf_set_oper_state(struct nwif_iface_conf *conf, uint8_t oper_state)
{
	nwif_iface_conf_assert(conf);
	nwif_assert(nwif_iface_oper_state_isok(oper_state));

	if (nwif_iface_conf_has_attr(conf, NWIF_OPER_STATE_ATTR) &&
	    (conf->data[0].oper_state == oper_state))
		return;

	conf->data[0].oper_state = oper_state;

	nwif_iface_conf_set_attr(conf, NWIF_OPER_STATE_ATTR);
}

void
nwif_iface_conf_clear_oper_state(struct nwif_iface_conf *conf)
{
	nwif_iface_conf_assert(conf);
	nwif_assert(conf->state != NWIF_IFACE_CONF_EMPTY_STATE);

	nwif_iface_conf_clear_attr(conf, NWIF_OPER_STATE_ATTR);
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
	nwif_assert(unet_mtu_isok(mtu));

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
	kvs_assert(conf);

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
	kvs_assert(conf);

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
