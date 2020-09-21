#ifndef _NWIF_IFACE_PRIV_H
#define _NWIF_IFACE_PRIV_H

#include "common.h"
#include <kvstore/table.h>
#include <kvstore/autorec.h>
#include <utils/net.h>
#include <net/if.h>

struct nwif_iface_conf;
struct nwif_iface_conf_data;

/******************************************************************************
 * Interface configuration table handling
 ******************************************************************************/

typedef int (nwif_iface_conf_check_data_fn)
            (uint64_t                           id,
             const struct nwif_iface_conf_data *data);

typedef int (nwif_iface_conf_bind_indx_fn)(const struct kvs_chunk *item,
                                           struct kvs_chunk       *skey);

struct nwif_iface_conf_impl {
	size_t                         data_size;
	nwif_iface_conf_bind_indx_fn  *bind_syspath;
	nwif_iface_conf_bind_indx_fn  *bind_hwaddr;
	nwif_iface_conf_check_data_fn *check_data;
};

#define nwif_iface_conf_assert_impl(_impl) \
	nwif_assert(_impl); \
	nwif_assert((_impl)->data_size > sizeof(struct nwif_iface_conf_data)); \
	nwif_assert((_impl)->bind_syspath); \
	nwif_assert((_impl)->bind_hwaddr); \
	nwif_assert((_impl)->check_data)

enum nwif_iface_conf_idx_id {
	NWIF_IFACE_CONF_NAME_IID,
	NWIF_IFACE_CONF_SYSPATH_IID,
	NWIF_IFACE_CONF_HWADDR_IID,
	NWIF_IFACE_CONF_IID_NR
};

extern const struct kvs_table_desc nwif_iface_conf_desc;

static inline int
nwif_iface_conf_del_byid(const struct kvs_table *table,
                         const struct kvs_xact  *xact,
                         uint64_t                id)
{
	return kvs_autorec_del_byid(kvs_table_get_data_store(table), xact, id);
}

extern int
nwif_iface_conf_del_byname(const struct kvs_table *table,
                           const struct kvs_xact  *xact,
                           const char             *name,
                           size_t                  len);

extern struct nwif_iface_conf *
nwif_iface_conf_create_from_rec(const struct kvs_table *table,
                                uint64_t                id,
                                const struct kvs_chunk *item);

extern struct nwif_iface_conf *
nwif_iface_conf_create_byid(const struct kvs_table *table,
                            const struct kvs_xact  *xact,
                            uint64_t                id);

extern struct nwif_iface_conf *
nwif_iface_conf_create_byname(const struct kvs_table *table,
                              const struct kvs_xact  *xact,
                              const char             *name,
                              size_t                  len);

/******************************************************************************
 * Interface configuration table iterator handling
 ******************************************************************************/

static inline int
nwif_iface_conf_iter_first(const struct kvs_iter   *iter,
                           uint64_t                *id,
                           struct kvs_chunk        *item)
{
	return kvs_autorec_iter_first(iter, id, item);
}

static inline int
nwif_iface_conf_iter_next(const struct kvs_iter   *iter,
                          uint64_t                *id,
                          struct kvs_chunk        *item)
{
	return kvs_autorec_iter_next(iter, id, item);
}

static inline int
nwif_iface_conf_init_iter(const struct kvs_table *table,
                          const struct kvs_xact  *xact,
                          struct kvs_iter        *iter)
{
	return kvs_autorec_init_iter(kvs_table_get_data_store(table),
	                             xact,
	                             iter);
}

static inline int
nwif_iface_conf_fini_iter(const struct kvs_iter *iter)
{
	return kvs_autorec_fini_iter(iter);
}

/******************************************************************************
 * Interface configuration handling
 ******************************************************************************/

struct nwif_iface_conf_data {
	enum nwif_iface_type type;
	unsigned int         attr_mask;
	char                 name[IFNAMSIZ];
	uint8_t              oper_state;
	uint32_t             mtu;
};

#define nwif_iface_conf_assert_data(_data) \
	nwif_assert(_data); \
	nwif_assert((_data)->type >= 0); \
	nwif_assert((_data)->type < NWIF_IFACE_TYPE_NR); \
	nwif_assert(!nwif_iface_conf_data_has_attr((_data), NWIF_NAME_ATTR) || \
	            (unet_check_iface_name((_data)->name) > 0)); \
	nwif_assert(!nwif_iface_conf_data_has_attr((_data), NWIF_MTU_ATTR) || \
	            unet_mtu_isok((_data)->mtu)); \
	nwif_assert(!nwif_iface_conf_data_has_attr((_data), \
	                                           NWIF_OPER_STATE_ATTR) || \
	            nwif_iface_oper_state_isok((_data)->oper_state))

static inline bool
nwif_iface_conf_data_has_attr(const struct nwif_iface_conf_data *data,
                              enum nwif_attr_type                attr)
{
	nwif_assert(data);
	nwif_assert(attr);
	nwif_assert(attr < NWIF_ATTR_NR);

	return !!(data->attr_mask & attr);
}

static inline void
nwif_iface_conf_data_set_attr(struct nwif_iface_conf_data *data,
                              enum nwif_attr_type          attr)
{
	nwif_assert(data);
	nwif_assert(attr);
	nwif_assert(attr < NWIF_ATTR_NR);

	data->attr_mask |= attr;
}

static inline void
nwif_iface_conf_data_clear_attr(struct nwif_iface_conf_data *data,
                                enum nwif_attr_type          attr)
{
	nwif_assert(data);
	nwif_assert(attr);
	nwif_assert(attr < NWIF_ATTR_NR);

	data->attr_mask &= ~attr;
}

enum nwif_iface_conf_state {
	NWIF_IFACE_CONF_EMPTY_STATE,
	NWIF_IFACE_CONF_CLEAN_STATE,
	NWIF_IFACE_CONF_DIRTY_STATE,
	NWIF_IFACE_CONF_FAIL_STATE
};

struct nwif_iface_conf {
	enum nwif_iface_conf_state   state;
	const struct kvs_table      *table;
	uint64_t                     id;
	struct nwif_iface_conf_data  data[0];
};

#define nwif_iface_conf_assert(_conf) \
	nwif_assert((_conf)->state != NWIF_IFACE_CONF_FAIL_STATE); \
	nwif_iface_conf_assert_data((_conf)->data)

static inline bool
nwif_iface_conf_has_attr(const struct nwif_iface_conf *conf,
                         enum nwif_attr_type           attr)
{
	return nwif_iface_conf_data_has_attr(conf->data, attr);
}

static inline void
nwif_iface_conf_set_attr(struct nwif_iface_conf *conf, enum nwif_attr_type attr)
{
	conf->state = NWIF_IFACE_CONF_DIRTY_STATE;
	nwif_iface_conf_data_set_attr(conf->data, attr);
}

static inline void
nwif_iface_conf_clear_attr(struct nwif_iface_conf *conf,
                           enum nwif_attr_type     attr)
{
	if (nwif_iface_conf_has_attr(conf, attr)) {
		conf->state = NWIF_IFACE_CONF_DIRTY_STATE;
		nwif_iface_conf_data_clear_attr(conf->data, attr);
	}
}

static inline uint64_t
nwif_iface_conf_get_id(const struct nwif_iface_conf *conf)
{
	nwif_iface_conf_assert(conf);
	nwif_assert(conf->state != NWIF_IFACE_CONF_EMPTY_STATE);

	return conf->id;
}

static inline enum nwif_iface_type
nwif_iface_conf_get_type(const struct nwif_iface_conf *conf)
{
	nwif_iface_conf_assert(conf);
	nwif_assert(conf->state != NWIF_IFACE_CONF_EMPTY_STATE);

	return conf->data[0].type;
}

extern const char *
nwif_iface_conf_get_name(const struct nwif_iface_conf *conf);

extern void
nwif_iface_conf_set_name(struct nwif_iface_conf *conf,
                         const char             *name,
                         size_t                  len);

extern void
nwif_iface_conf_clear_name(struct nwif_iface_conf *conf);

extern void
nwif_iface_conf_get_oper_state(const struct nwif_iface_conf *conf,
                               uint8_t                      *oper_state);

extern void
nwif_iface_conf_set_oper_state(struct nwif_iface_conf *conf,
                               uint8_t                 oper_state);

extern void
nwif_iface_conf_clear_oper_state(struct nwif_iface_conf *conf);

extern int
nwif_iface_conf_get_mtu(const struct nwif_iface_conf *conf, uint32_t *mtu);

extern void
nwif_iface_conf_set_mtu(struct nwif_iface_conf *conf, uint32_t mtu);

extern void
nwif_iface_conf_clear_mtu(struct nwif_iface_conf *conf);

extern int
nwif_iface_conf_reload(struct nwif_iface_conf *conf,
                       const struct kvs_xact  *xact);

extern int
nwif_iface_conf_del(struct nwif_iface_conf *conf, const struct kvs_xact *xact);

extern int
nwif_iface_conf_save(struct nwif_iface_conf *conf, const struct kvs_xact *xact);

extern void
nwif_iface_conf_init(struct nwif_iface_conf *conf,
                     enum nwif_iface_type    type,
                     const struct kvs_table *table);

static inline struct nwif_iface_conf *
nwif_iface_conf_alloc(size_t data_size)
{
	nwif_assert(data_size > sizeof(struct nwif_iface_conf_data));

	return malloc(sizeof(struct nwif_iface_conf) + data_size);
}

static inline void
nwif_iface_conf_destroy(struct nwif_iface_conf *conf)
{
	nwif_assert(conf);

	free(conf);
}

#endif /* _NWIF_IFACE_PRIV_H */
