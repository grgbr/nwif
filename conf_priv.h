#ifndef _NWIF_CONF_PRIV_H
#define _NWIF_CONF_PRIV_H

#include <kvstore/repo.h>

enum nwif_conf_table_id {
	NWIF_CONF_IFACE_TID,
#if 0
	NWIF_CONF_ADDR_TID,
#endif
	NWIF_CONF_TID_NR
};

static inline const struct kvs_table *
nwif_conf_get_iface_table(const struct kvs_repo *repo)
{
	return kvs_repo_get_table(repo, NWIF_CONF_IFACE_TID);
}

#if 0
static inline const struct kvs_table *
nwif_conf_get_addr_table(const struct kvs_repo *repo)
{
	return kvs_repo_get_table(repo, NWIF_CONF_ADDR_TID);
}
#endif

extern int
nwif_conf_begin_xact(const struct kvs_repo *repo,
                     const struct kvs_xact *parent,
                     struct kvs_xact       *xact,
                     unsigned int           flags);

extern int
nwif_conf_open(struct kvs_repo *repo,
               const char      *path,
               unsigned int     flags,
               mode_t           mode);

extern int
nwif_conf_close(const struct kvs_repo *repo);

extern struct kvs_repo *
nwif_conf_create(void);

extern void
nwif_conf_destroy(struct kvs_repo *repo);

extern const char *
nwif_conf_strerror(int error);

#endif /* _NWIF_CONF_PRIV_H */
