#ifndef _NWIF_IFACE_PRIV_H
#define _NWIF_IFACE_PRIV_H

#include "common.h"
#include "state_priv.h"
#include <nlink/iface.h>
#include <kvstore/table.h>
#include <kvstore/autorec.h>
#include <utils/net.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if.h>

/******************************************************************************
 * Interface configuration table handling
 ******************************************************************************/

struct nwif_iface_conf;
struct nwif_iface_conf_data;

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

extern struct nwif_iface_conf *
nwif_iface_conf_create_bysyspath(const struct kvs_table *table,
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
	uint8_t              admin_state;
	uint32_t             mtu;
};

#define nwif_iface_conf_assert_data(_data) \
	nwif_assert(_data); \
	nwif_assert((_data)->type >= 0); \
	nwif_assert((_data)->type < NWIF_IFACE_TYPE_NR); \
	nwif_assert(!nwif_iface_conf_data_has_attr((_data), NWIF_NAME_ATTR) || \
	            (unet_check_iface_name((_data)->name) > 0)); \
	nwif_assert(!nwif_iface_conf_data_has_attr((_data), \
	                                           NWIF_ADMIN_STATE_ATTR) || \
	            unet_iface_admin_state_isok((_data)->admin_state)); \
	nwif_assert(!nwif_iface_conf_data_has_attr((_data), NWIF_MTU_ATTR) || \
	            unet_iface_mtu_isok((_data)->mtu))

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
nwif_iface_conf_get_admin_state(const struct nwif_iface_conf *conf,
                                uint8_t                      *state);

extern void
nwif_iface_conf_set_admin_state(struct nwif_iface_conf *conf, uint8_t state);

extern void
nwif_iface_conf_clear_admin_state(struct nwif_iface_conf *conf);

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

/******************************************************************************
 * Interface state handling
 ******************************************************************************/

struct nwif_iface_state;

typedef bool (nwif_iface_state_probe_type_fn)(const struct nlink_iface *attrs);

typedef int (nwif_iface_state_fill_attrs_fn)
            (struct nwif_iface_state  *state,
             const struct nlink_iface *iface);

typedef int (nwif_iface_state_apply_conf_fn)
            (struct nwif_iface_state      *state,
             struct nlmsghdr              *msg,
             const struct nwif_iface_conf *conf);

struct nwif_iface_state_impl {
	unsigned short                  arp_type;
	nwif_iface_state_probe_type_fn *probe_type;
	size_t                          size;
	nwif_iface_state_fill_attrs_fn *fill_attrs;
	nwif_iface_state_apply_conf_fn *apply_conf;
};

struct nwif_iface_state {
	struct nwif_state_sock *sock;
	int                     sysid;
	enum nwif_iface_type    type;
	char                    name[IFNAMSIZ];
	uint8_t                 admin_state;
	uint8_t                 oper_state;
	uint8_t                 carrier_state;
	uint32_t                mtu;
};

#define nwif_iface_state_assert(_state) \
	nwif_assert(_state); \
	nwif_assert((_state)->sock); \
	nlink_assert_sock(&(_state)->sock->nlink); \
	nwif_assert((_state)->sysid > 0); \
	nwif_assert((_state)->type >= 0); \
	nwif_assert((_state)->type < NWIF_IFACE_TYPE_NR); \
	nwif_assert(unet_check_iface_name((_state)->name) > 0); \
	nwif_assert(unet_iface_admin_state_isok((_state)->admin_state)); \
	nwif_assert(unet_iface_oper_state_isok((_state)->oper_state)); \
	nwif_assert(unet_iface_carrier_state_isok((_state)->carrier_state)); \
	nwif_assert(unet_iface_mtu_isok((_state)->mtu))

static inline int
nwif_iface_state_get_id(const struct nwif_iface_state *state)
{
	nwif_iface_state_assert(state);

	return state->sysid;
}

static inline enum nwif_iface_type
nwif_iface_state_get_type(const struct nwif_iface_state *state)
{
	nwif_iface_state_assert(state);

	return state->type;
}

static inline const char *
nwif_iface_state_get_name(const struct nwif_iface_state *state)
{
	nwif_iface_state_assert(state);

	return state->name;
}

static inline uint8_t
nwif_iface_state_get_admin_state(const struct nwif_iface_state *state)
{
	nwif_iface_state_assert(state);

	return state->admin_state;
}

static inline uint8_t
nwif_iface_state_get_oper_state(const struct nwif_iface_state *state)
{
	nwif_iface_state_assert(state);

	return state->oper_state;
}

static inline uint8_t
nwif_iface_state_get_carrier(const struct nwif_iface_state *state)
{
	nwif_iface_state_assert(state);

	return state->carrier_state;
}

static inline uint32_t
nwif_iface_state_get_mtu(const struct nwif_iface_state *state)
{
	nwif_iface_state_assert(state);

	return state->mtu;
}

#define nwif_iface_state_assert_attrs(_attrs) \
	nwif_assert((_attrs)->type < ARPHRD_NONE); \
	nwif_assert((_attrs)->index > 0); \
	nwif_assert(unet_iface_admin_state_isok((_attrs)->admin_state)); \
	nwif_assert(unet_check_iface_name((_attrs)->name) == \
	            (ssize_t)(_attrs)->name_len); \
	nwif_assert(unet_iface_mtu_isok((_attrs)->mtu)); \
	nwif_assert(unet_iface_oper_state_isok((_attrs)->oper_state)); \
	nwif_assert(unet_iface_carrier_state_isok((_attrs)->carrier_state))

static inline int
nwif_iface_state_parse_msg(const struct nlmsghdr *msg,
                           struct nlink_iface    *attrs)
{
	int err;

	err = nlink_iface_parse_msg(msg, attrs);
	if (err)
		return err;

	nwif_iface_state_assert_attrs(attrs);

	return 0;
}

extern int
nwif_iface_state_start_apply(struct nwif_iface_state      *iface,
                             const struct nwif_iface_conf *conf);

extern int
nwif_iface_state_update(struct nwif_iface_state  *iface,
                        const struct nlink_iface *attrs);

static inline void
nwif_iface_state_init(struct nwif_iface_state *state,
                      int                      sysid,
                      enum nwif_iface_type     type,
                      struct nwif_state_sock  *sock)
{
	nwif_assert(state);
	nwif_assert(sysid > 0);
	nwif_assert(type >= 0);
	nwif_assert(type < NWIF_IFACE_TYPE_NR);
	nlink_assert_sock(&sock->nlink);

	state->sock = sock;
	state->sysid = sysid;
	state->type = type;
}

struct nwif_iface_state *
nwif_iface_state_create(struct nwif_state_sock   *sock,
                        const struct nlink_iface *attrs);

struct nwif_iface_state *
nwif_iface_state_create_from_msg(struct nwif_state_sock *sock,
                                 const struct nlmsghdr  *msg);

static inline void
nwif_iface_state_destroy(struct nwif_iface_state *state)
{
	nwif_assert(state);

	free(state);
}

/******************************************************************************
 * Top-level interface handling
 ******************************************************************************/

struct kvs_repo;

struct nwif_iface {
	struct pavl_node         sysid_node;
	struct nwif_iface_conf  *conf;
	struct nwif_iface_state *state;
};

static inline struct nwif_iface_conf *
nwif_iface_get_conf(const struct nwif_iface *iface)
{
	nwif_assert(iface);

	return iface->conf;
}

static inline struct nwif_iface_state *
nwif_iface_get_state(const struct nwif_iface *iface)
{
	nwif_assert(iface);

	return iface->state;
}

extern int
nwif_iface_load(struct nwif_iface     *iface,
                const struct kvs_repo *conf,
                const struct kvs_xact *xact);

static inline int
nwif_iface_start_apply(struct nwif_iface *iface)
{
	nwif_assert(iface);
	nwif_assert(iface->state);
	nwif_assert(iface->conf);

	return nwif_iface_state_start_apply(iface->state, iface->conf);
}

extern struct nwif_iface *
nwif_iface_create(struct nwif_state_sock   *sock,
                  const struct nlink_iface *attrs);

extern void
nwif_iface_destroy(struct nwif_iface *iface);

/******************************************************************************
 * Interface cache handling
 ******************************************************************************/

struct nwif_iface_cache {
	struct pavl_tree sysid_avl;
};

static inline struct nwif_iface *
nwif_iface_cache_get_first(const struct nwif_iface_cache *cache)
{
	nwif_assert(cache);

	struct pavl_node *node;

	node = pavl_iter_first_inorder(&cache->sysid_avl);

	return node ? containerof(node, struct nwif_iface, sysid_node) : NULL;
}

static inline struct nwif_iface *
nwif_iface_cache_get_next(const struct nwif_iface *iface)
{
	nwif_assert(iface);

	struct pavl_node *node;

	node = pavl_iter_next_inorder(&iface->sysid_node);

	return node ? containerof(node, struct nwif_iface, sysid_node) : NULL;
}

static inline struct nwif_iface *
nwif_iface_cache_scan_byid(const struct nwif_iface_cache *cache,
                           int                            sysid,
                           struct pavl_scan              *scan)
{
	nwif_assert(cache);
	nwif_assert(sysid > 0);
	nwif_assert(scan);

	struct pavl_node *node;

	node = pavl_scan_key(&cache->sysid_avl, (void *)sysid, scan);

	return node ? containerof(node, struct nwif_iface, sysid_node) : NULL;
}

static inline void
nwif_iface_cache_append(struct nwif_iface_cache *cache,
                        const struct pavl_scan  *scan,
                        struct nwif_iface       *iface)
{
	nwif_assert(cache);
	nwif_assert(scan);
	nwif_assert(iface);

	pavl_append_scan_node(&cache->sysid_avl, &iface->sysid_node, scan);
}

static inline void
nwif_iface_cache_clear(struct nwif_iface_cache *cache)
{
	nwif_assert(cache);

	pavl_clear_tree(&cache->sysid_avl);
}

extern void
nwif_iface_cache_init(struct nwif_iface_cache *cache);

static inline void
nwif_iface_cache_fini(struct nwif_iface_cache *cache)
{
	nwif_assert(cache);

	pavl_fini_tree(&cache->sysid_avl);
}

#endif /* _NWIF_IFACE_PRIV_H */
