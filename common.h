#ifndef _NWIF_COMMON_H
#define _NWIF_COMMON_H

#include <nwif/config.h>
#include <nwif/nwif.h>
#include <kvstore/autorec.h>
#include <net/if.h>

#if defined(CONFIG_NWIF_ASSERT)

#include <utils/assert.h>

#define nwif_assert(_expr) \
	uassert("nwif", _expr)

#else  /* !defined(CONFIG_NWIF_ASSERT) */

#define nwif_assert(_expr)

#endif /* defined(CONFIG_NWIF_ASSERT) */

enum nwif_attr_type {
	NWIF_NAME_ATTR       = (1U << 0),
	NWIF_OPER_STATE_ATTR = (1U << 1),
	NWIF_MTU_ATTR        = (1U << 2),
	NWIF_SYSPATH_ATTR    = (1U << 3),
	NWIF_HWADDR_ATTR     = (1U << 4),
	NWIF_ATTR_NR
};

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

/******************************************************************************
 * Base interface configuration utils
 ******************************************************************************/

enum nwif_iface_conf_state {
	NWIF_IFACE_CONF_EMPTY_STATE,
	NWIF_IFACE_CONF_CLEAN_STATE,
	NWIF_IFACE_CONF_DIRTY_STATE,
	NWIF_IFACE_CONF_FAIL_STATE
};

struct nwif_iface_conf_data {
	enum nwif_iface_type type;
	unsigned int         attr_mask;
	char                 name[IFNAMSIZ];
	uint8_t              oper_state;
	uint32_t             mtu;
};

struct nwif_iface_conf {
	enum nwif_iface_conf_state  state;
	struct kvs_autorec_id       id;
	struct nwif_iface_conf_data data[0];
};

#define nwif_iface_conf_assert_data(_data) \
	nwif_assert((_data)->type >= 0); \
	nwif_assert((_data)->type < NWIF_TYPE_NR); \
	nwif_assert(!nwif_iface_conf_data_has_attr(_data, NWIF_NAME_ATTR) || \
	            (unet_check_iface_name((_data)->name) > 0)); \
	nwif_assert(!nwif_iface_conf_data_has_attr(_data, \
	                                           NWIF_OPER_STATE_ATTR) || \
	            nwif_iface_oper_state_isok((_data)->oper_state)); \
	nwif_assert(!nwif_iface_conf_data_has_attr(_data, NWIF_MTU_ATTR) || \
	            unet_mtu_isok((_data)->mtu))

static inline bool
nwif_iface_conf_data_has_attr(const struct nwif_iface_conf_data *data,
                              unsigned int                       attr_mask)
{
	nwif_assert(data);
	nwif_assert(attr_mask);

	return !!(data->attr_mask & attr_mask);
}

static inline bool
nwif_iface_conf_has_attr(const struct nwif_iface_conf *conf,
                         unsigned int                  attr_mask)
{
	return nwif_iface_conf_data_has_attr(conf->data, attr_mask);
}

static inline void
nwif_iface_conf_set_attr(struct nwif_iface_conf *conf, enum nwif_attr_type attr)
{
	nwif_assert(conf);
	nwif_assert(attr);
	nwif_assert(attr < NWIF_ATTR_NR);

	conf->data[0].attr_mask |= attr;
	conf->state = NWIF_IFACE_CONF_DIRTY_STATE;
}

extern int
nwif_iface_conf_check_data(const struct kvs_autorec_desc *desc,
                           enum nwif_iface_type           type,
                           size_t                         size);

static inline void
nwif_iface_conf_init(struct nwif_iface_conf *conf, enum nwif_iface_type type)
{
	conf->state = NWIF_IFACE_CONF_EMPTY_STATE;
	conf->id = KVS_AUTOREC_NONE;
	conf->data[0].type = type;
	conf->data[0].attr_mask = 0U;
}

enum nwif_iface_conf_store_id {
	NWIF_IFACE_CONF_NAMES_SID    = 0,
#if 0
	NWIF_IFACE_CONF_SYSPATHS_SID = 1,
	NWIF_IFACE_CONF_HWADDRS_SID  = 2,
#endif
	NWIF_IFACE_CONF_SID_NR
};

struct nwif_iface_conf_table {
	int               open_cnt;
	struct kvs_store  data;
	struct kvs_store  idx[NWIF_IFACE_CONF_SID_NR];
};

extern int
nwif_iface_conf_open_table(struct nwif_iface_conf_table *table,
                           const struct kvs_depot       *depot,
                           const struct kvs_xact        *xact);

extern int
nwif_iface_conf_close_table(struct nwif_iface_conf_table *table);

struct nwif_conf_repo {
	struct nwif_iface_conf_table ifaces;
	struct kvs_depot             depot;
};

/******************************************************************************
 * Interface fabrics
 ******************************************************************************/

#if defined(CONFIG_NWIF_ETHER)

extern int
nwif_ether_conf_save(struct nwif_iface_conf *conf,
                     const struct kvs_xact  *xact,
                     struct nwif_conf_repo  *repo);

extern int
nwif_ether_conf_load_from_desc(struct nwif_iface_conf        *conf,
                               const struct kvs_autorec_desc *desc);

extern struct nwif_iface_conf *
nwif_ether_conf_create_from_desc(const struct kvs_autorec_desc *desc);

#else /* !defined(CONFIG_NWIF_ETHER) */

static inline int
nwif_ether_conf_save(struct nwif_iface_conf *conf __unused,
                     const struct kvs_xact  *xact __unused,
                     struct nwif_conf_repo  *repo __unused)
{
	return -ENOSYS;
}

static inline int
nwif_ether_conf_load_from_desc(struct nwif_iface_conf        *conf __unused,
                               const struct kvs_autorec_desc *desc __unused)
{
	return -ENOSYS;
}

static inline struct nwif_iface_conf *
nwif_ether_conf_create_from_desc(const struct kvs_autorec_desc *desc __unused)
{
	errno = ENOSYS;
	return NULL;
}

#endif /* defined(CONFIG_NWIF_ETHER) */

#endif /* _NWIF_COMMON_H */
