#ifndef _NWIF_CONF_H
#define _NWIF_CONF_H

#include <nwif/nwif.h>
#include <kvstore/autorec.h>

struct nwif_conf_repo;
struct nwif_iface_conf;

extern struct kvs_autorec_id
nwif_iface_conf_get_id(const struct nwif_iface_conf *conf);

extern enum nwif_iface_type
nwif_iface_conf_get_type(const struct nwif_iface_conf *conf);

extern const char *
nwif_iface_conf_get_name(const struct nwif_iface_conf *conf);

extern void
nwif_iface_conf_set_name(struct nwif_iface_conf *conf,
                         const char             *name,
                         size_t                  len);

extern void
nwif_iface_conf_get_oper_state(const struct nwif_iface_conf *conf,
                               uint8_t                      *oper_state);

extern void
nwif_iface_conf_set_oper_state(struct nwif_iface_conf *conf,
                               uint8_t                 oper_state);

extern int
nwif_iface_conf_get_mtu(const struct nwif_iface_conf *conf, uint32_t *mtu);

extern void
nwif_iface_conf_set_mtu(struct nwif_iface_conf *conf, uint32_t mtu);

extern int
nwif_iface_conf_save(struct nwif_iface_conf *conf,
                     const struct kvs_xact  *xact,
                     struct nwif_conf_repo  *repo);

extern int
nwif_iface_conf_reload(struct nwif_iface_conf *conf,
                       const struct kvs_xact  *xact,
                       struct nwif_conf_repo  *repo);

extern int
nwif_iface_conf_del_byid(struct kvs_autorec_id        id,
                         const struct kvs_xact       *xact,
                         const struct nwif_conf_repo *repo);

extern int
nwif_iface_conf_del_byname(const char                  *name,
                           size_t                       len,
                           const struct kvs_xact       *xact,
                           const struct nwif_conf_repo *repo);

extern struct nwif_iface_conf *
nwif_iface_conf_create_from_desc(const struct kvs_autorec_desc *desc);

extern struct nwif_iface_conf *
nwif_iface_conf_create_byid(struct kvs_autorec_id        id,
                            const struct kvs_xact       *xact,
                            const struct nwif_conf_repo *repo);

extern struct nwif_iface_conf *
nwif_iface_conf_create_byname(const char                  *name,
                              size_t                       len,
                              const struct kvs_xact       *xact,
                              const struct nwif_conf_repo *repo);

extern void
nwif_iface_conf_destroy(struct nwif_iface_conf *conf);

extern int
nwif_iface_conf_iter_first(const struct kvs_iter   *iter,
                           struct kvs_autorec_desc *desc);

extern int
nwif_iface_conf_iter_next(const struct kvs_iter   *iter,
                          struct kvs_autorec_desc *desc);

extern int
nwif_iface_conf_init_iter(const struct nwif_conf_repo *repo,
                          const struct kvs_xact       *xact,
                          struct kvs_iter             *iter);

extern int
nwif_iface_conf_fini_iter(const struct kvs_iter *iter);

extern const char *
nwif_conf_strerror(int error);

extern int
nwif_conf_begin_xact(const struct nwif_conf_repo *repo,
                     const struct kvs_xact       *parent,
                     struct kvs_xact             *xact,
                     unsigned int                 flags);

extern int
nwif_conf_rollback_xact(const struct kvs_xact *xact);

extern int
nwif_conf_commit_xact(const struct kvs_xact *xact);

extern int
nwif_conf_open(struct nwif_conf_repo *repo,
               const char            *path,
               unsigned int           flags,
               mode_t                 mode);

extern int
nwif_conf_close(struct nwif_conf_repo *repo);

extern struct nwif_conf_repo *
nwif_conf_alloc(void);

#endif /* _NWIF_CONF_H */
