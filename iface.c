#include "common.h"
#include <nwif/conf.h>
#include <utils/string.h>
#include <utils/net.h>
#include <stdio.h>
#include <stdlib.h>
#include <glob.h>
#include <errno.h>
#include <sys/stat.h>
#include <linux/if.h>

#define NWIF_SYSNETDEV_IFINDEX_PATTERN "net/*/ifindex"
#define NWIF_IFACE_CONF_BASENAME       "iface"

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
 * Base interface configuration handling
 ******************************************************************************/

#define nwif_iface_conf_assert_get(_conf) \
	nwif_assert((_conf)->state != NWIF_IFACE_CONF_EMPTY_STATE); \
	nwif_assert((_conf)->state != NWIF_IFACE_CONF_FAIL_STATE); \
	nwif_iface_conf_assert_data((_conf)->data)

#define nwif_iface_conf_assert_set(_conf) \
	nwif_assert((_conf)->state != NWIF_IFACE_CONF_FAIL_STATE); \
	nwif_iface_conf_assert_data((_conf)->data)

struct kvs_autorec_id
nwif_iface_conf_get_id(const struct nwif_iface_conf *conf)
{
	nwif_iface_conf_assert_get(conf);

	return conf->id;
}

enum nwif_iface_type
nwif_iface_conf_get_type(const struct nwif_iface_conf *conf)
{
	nwif_iface_conf_assert_get(conf);

	return conf->data[0].type;
}

const char *
nwif_iface_conf_get_name(const struct nwif_iface_conf *conf)
{
	nwif_iface_conf_assert_get(conf);

	if (!nwif_iface_conf_has_attr(conf, NWIF_NAME_ATTR))
		return NULL;

	return conf->data[0].name;
}

void
nwif_iface_conf_set_name(struct nwif_iface_conf *conf,
                         const char             *name,
                         size_t                  len)
{
	nwif_iface_conf_assert_set(conf);
	nwif_assert(unet_check_iface_name(name) == (ssize_t)len);

	memcpy(conf->data[0].name, name, len);
	conf->data[0].name[len] = '\0';

	nwif_iface_conf_set_attr(conf, NWIF_NAME_ATTR);
}

void
nwif_iface_conf_get_oper_state(const struct nwif_iface_conf *conf,
                               uint8_t                      *oper_state)
{
	nwif_iface_conf_assert_get(conf);
	nwif_assert(oper_state);

	if (nwif_iface_conf_has_attr(conf, NWIF_OPER_STATE_ATTR))
		*oper_state = conf->data[0].oper_state;
	else
		*oper_state = IF_OPER_DOWN;
}

void
nwif_iface_conf_set_oper_state(struct nwif_iface_conf *conf, uint8_t oper_state)
{
	nwif_iface_conf_assert_set(conf);
	nwif_assert(nwif_iface_oper_state_isok(oper_state));

	conf->data[0].oper_state = oper_state;

	nwif_iface_conf_set_attr(conf, NWIF_OPER_STATE_ATTR);
}

int
nwif_iface_conf_get_mtu(const struct nwif_iface_conf *conf, uint32_t *mtu)
{
	nwif_iface_conf_assert_get(conf);
	nwif_assert(mtu);

	if (!nwif_iface_conf_has_attr(conf, NWIF_MTU_ATTR))
		return -ENODATA;

	*mtu = conf->data[0].mtu;

	return 0;
}

void
nwif_iface_conf_set_mtu(struct nwif_iface_conf *conf, uint32_t mtu)
{
	nwif_iface_conf_assert_set(conf);
	nwif_assert(unet_mtu_isok(mtu));

	conf->data[0].mtu = mtu;

	nwif_iface_conf_set_attr(conf, NWIF_MTU_ATTR);
}

int
nwif_iface_conf_check_data(const struct kvs_autorec_desc *desc,
                           enum nwif_iface_type           type,
                           size_t                         size)
{
	const struct nwif_iface_conf_data *data;

	nwif_assert(desc);
	nwif_assert(desc->data);
	nwif_assert(desc->size > sizeof(*data));
	nwif_assert(type >= 0);
	nwif_assert(type < NWIF_TYPE_NR);
	nwif_assert(size > sizeof(*data));

	if (desc->size != size)
		return -EMSGSIZE;

	data = (struct nwif_iface_conf_data *)desc->data;
	if (data->type != type)
		return -ENOMSG;

	if (nwif_iface_conf_data_has_attr(data, NWIF_NAME_ATTR) &&
	    (unet_check_iface_name(data->name) < 0))
		return -EBADMSG;

	if (nwif_iface_conf_data_has_attr(data, NWIF_OPER_STATE_ATTR) &&
	    !nwif_iface_oper_state_isok(data->oper_state))
		return -EBADMSG;

	if (nwif_iface_conf_data_has_attr(data, NWIF_MTU_ATTR) &&
	    !unet_mtu_isok(data->mtu))
		return -EBADMSG;

	return 0;
}

int
nwif_iface_conf_iter_first(const struct kvs_iter   *iter,
                           struct kvs_autorec_desc *desc)
{
	return kvs_autorec_iter_first(iter, desc);
}

int
nwif_iface_conf_iter_next(const struct kvs_iter   *iter,
                          struct kvs_autorec_desc *desc)
{
	return kvs_autorec_iter_next(iter, desc);
}

int
nwif_iface_conf_init_iter(const struct nwif_conf_repo *repo,
                          const struct kvs_xact       *xact,
                          struct kvs_iter             *iter)
{
	return kvs_autorec_init_iter(&repo->ifaces.data, xact, iter);
}

int
nwif_iface_conf_fini_iter(const struct kvs_iter *iter)
{
	return kvs_autorec_fini_iter(iter);
}

int
nwif_iface_conf_save(struct nwif_iface_conf *conf,
                     const struct kvs_xact  *xact,
                     struct nwif_conf_repo  *repo)
{
	nwif_assert(conf);

	int err;

	switch (conf->state) {
	case NWIF_IFACE_CONF_EMPTY_STATE:
		return -EBADFD;

	case NWIF_IFACE_CONF_CLEAN_STATE:
		return 0;

	case NWIF_IFACE_CONF_DIRTY_STATE:
		break;

	case NWIF_IFACE_CONF_FAIL_STATE:
	default:
		nwif_assert(0);
	}

	nwif_assert(conf->data[0].type >= 0);
	nwif_assert(conf->data[0].type < NWIF_TYPE_NR);
	nwif_assert(!nwif_iface_conf_has_attr(conf, NWIF_NAME_ATTR) ||
	            (unet_check_iface_name(conf->data[0].name) > 0));
	nwif_assert(!nwif_iface_conf_has_attr(conf, NWIF_MTU_ATTR) ||
	            unet_mtu_isok(conf->data[0].mtu));
	nwif_assert(!nwif_iface_conf_has_attr(conf, NWIF_OPER_STATE_ATTR) ||
	            nwif_iface_oper_state_isok(conf->data[0].oper_state));

	switch (conf->data[0].type) {
	case NWIF_ETHER_IFACE_TYPE:
		err = nwif_ether_conf_save(conf, xact, repo);
		break;

	default:
		return -ENOTSUP;
	}

	conf->state = !err ? NWIF_IFACE_CONF_CLEAN_STATE :
	                     NWIF_IFACE_CONF_FAIL_STATE;

	return err;
}

static int
nwif_iface_conf_check_desc(const struct kvs_autorec_desc *desc)
{
	nwif_assert(desc);
	nwif_assert(kvs_autorec_id_isok(desc->id));

	const struct nwif_iface_conf_data *data;

	data = (const struct nwif_iface_conf_data *)desc->data;
	if (!data)
		return -ENODATA;

	if (desc->size <= sizeof(*data))
		return -EMSGSIZE;

	return data->type;
}

int
nwif_iface_conf_reload(struct nwif_iface_conf *conf,
                       const struct kvs_xact  *xact,
                       struct nwif_conf_repo  *repo)
{
	nwif_assert(conf);
	nwif_assert(conf->state != NWIF_IFACE_CONF_EMPTY_STATE);
	nwif_assert(conf->data[0].type >= 0);
	nwif_assert(conf->data[0].type < NWIF_TYPE_NR);

	struct kvs_autorec_desc desc;
	int                     ret;

	ret = kvs_autorec_get_desc(&repo->ifaces.data, xact, conf->id, &desc);
	if (ret)
		return ret;

	ret = nwif_iface_conf_check_desc(&desc);
	if (ret < 0)
		return ret;

	switch (ret) {
	case NWIF_ETHER_IFACE_TYPE:
		return nwif_ether_conf_load_from_desc(conf, &desc);

	default:
		return -ENOTSUP;
	}
}

int
nwif_iface_conf_del_byid(struct kvs_autorec_id        id,
                         const struct kvs_xact       *xact,
                         const struct nwif_conf_repo *repo)
{
	return kvs_autorec_del(&repo->ifaces.data, xact, id);
}

struct nwif_iface_conf *
nwif_iface_conf_create_from_desc(const struct kvs_autorec_desc *desc)
{
	int ret;

	ret = nwif_iface_conf_check_desc(desc);
	if (ret < 0) {
		errno = -ret;
		return NULL;
	}

	switch (ret) {
	case NWIF_ETHER_IFACE_TYPE:
		return nwif_ether_conf_create_from_desc(desc);

	default:
		errno = ENOTSUP;
		return NULL;
	}
}

struct nwif_iface_conf *
nwif_iface_conf_create_byid(struct kvs_autorec_id        id,
                            const struct kvs_xact       *xact,
                            const struct nwif_conf_repo *repo)
{
	struct kvs_autorec_desc desc;
	int                     err;

	err = kvs_autorec_get_desc(&repo->ifaces.data, xact, id, &desc);
	if (err) {
		errno = -err;
		return NULL;
	}

	return nwif_iface_conf_create_from_desc(&desc);
}

void
nwif_iface_conf_destroy(struct nwif_iface_conf *conf)
{
	free(conf);
}

static ssize_t
nwif_iface_conf_bind_name_idx(const void  *pkey_data,
                              size_t       pkey_size,
                              const void  *pitem_data,
                              size_t       pitem_size,
                              void       **skey_data)
{
	nwif_assert(pkey_data);
	nwif_assert(pkey_size);
	nwif_assert(pitem_data);
	nwif_assert(pitem_size);
	nwif_assert(skey_data);

	struct nwif_iface_conf_data *data;

	if (pitem_size <= sizeof(*data))
		return -EMSGSIZE;

	data = (struct nwif_iface_conf_data *)pitem_data;
	nwif_iface_conf_assert_data(data);

	if (!nwif_iface_conf_data_has_attr(data, NWIF_NAME_ATTR))
		return 0;

	*skey_data = data->name;

	return strlen(data->name);
}

int
nwif_iface_conf_open_table(struct nwif_iface_conf_table *table,
                           const struct kvs_depot       *depot,
                           const struct kvs_xact        *xact)
{
	int err;

	table->open_cnt = 0;
	err = kvs_autorec_open(&table->data,
	                       depot,
	                       xact,
	                       NWIF_IFACE_CONF_BASENAME ".db",
	                       S_IRUSR | S_IWUSR);
	if (err)
		return err;

	err = kvs_open_index(&table->idx[table->open_cnt++],
	                     &table->data,
	                     depot,
	                     xact,
	                     NWIF_IFACE_CONF_BASENAME ".idx",
	                     "names",
	                     S_IRUSR | S_IWUSR,
	                     &nwif_iface_conf_bind_name_idx);
	if (err)
		return err;

#if 0
	err = kvs_open_index(&table->syspaths,
	                     &table->data,
	                     depot,
	                     &xact,
	                     NWIF_IFACE_CONF_BASENAME ".idx",
	                     "syspaths",
	                     S_IRUSR | S_IWUSR,
	                     &nwif_iface_conf_bind_sypath_idx);
	if (err)
		return err;

	err = kvs_open_index(&table->hwaddrs,
	                     &table->data,
	                     depot,
	                     &xact,
	                     NWIF_IFACE_CONF_BASENAME ".idx",
	                     "hwaddrs",
	                     S_IRUSR | S_IWUSR,
	                     &nwif_iface_conf_bind_hwaddr_idx);
	if (err)
		return err;
#endif

	return 0;
}

int
nwif_iface_conf_close_table(struct nwif_iface_conf_table *table)
{
	int ret = 0;

	while (!ret && table->open_cnt)
		ret = kvs_close_index(&table->idx[--table->open_cnt]);
	while (table->open_cnt)
		kvs_close_index(&table->idx[--table->open_cnt]);

	if (!ret)
		ret = kvs_autorec_close(&table->data);
	else
		kvs_autorec_close(&table->data);

	return ret;
}
