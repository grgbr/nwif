#include "conf_priv.h"
#include "iface_priv.h"
#include "addr_priv.h"

/* Restrict maximum transaction log file size to 512kB. */
#define NWIF_CONF_MAX_LOG_SIZE (512 << 10)

int
nwif_conf_begin_xact(const struct kvs_repo *repo,
                     const struct kvs_xact *parent,
                     struct kvs_xact       *xact,
                     unsigned int           flags)
{
	nwif_assert(repo);

	return kvs_begin_xact(&repo->depot, parent, xact, flags);
}

static const struct kvs_repo_desc nwif_conf_desc = {
	.tbl_nr = NWIF_CONF_TID_NR,
	.tables = {
		[NWIF_CONF_IFACE_TID] = &nwif_iface_conf_desc,
#if 0
		[NWIF_CONF_ADDR_TID]  = &nwif_addr_conf_desc
#endif
	}
};

int
nwif_conf_open(struct kvs_repo *repo,
               const char      *path,
               unsigned int     flags,
               mode_t           mode)
{
	return kvs_repo_open(repo,
	                     path,
	                     NWIF_CONF_MAX_LOG_SIZE,
	                     flags | KVS_DEPOT_PRIV,
	                     mode);
}

int
nwif_conf_close(const struct kvs_repo *repo)
{
	return kvs_repo_close(repo);
}

struct kvs_repo *
nwif_conf_create(void)
{
	return kvs_repo_create(&nwif_conf_desc);
}

void
nwif_conf_destroy(struct kvs_repo *repo)
{
	kvs_repo_destroy(repo);
}

const char *
nwif_conf_strerror(int err)
{
	return kvs_strerror(err);
}

#if 0

int
nwif_conf_commit_xact(const struct kvs_xact *xact)
{
	return kvs_commit_xact(xact);
}


int
nwif_conf_rollback_xact(const struct kvs_xact *xact)
{
	return kvs_rollback_xact(xact);
}

int
nwif_conf_open(struct nwif_conf_repo *repo,
               const char            *path,
               unsigned int           flags,
               mode_t                 mode)
{
	nwif_assert(repo);
	nwif_assert(!(flags & ~KVS_DEPOT_THREAD));

	int             err;
	struct kvs_xact xact;

	err = kvs_open_depot(&repo->depot,
	                     path,
	                     NWIF_CONF_MAX_LOG_SIZE,
	                     flags | KVS_DEPOT_PRIV,
	                     mode);
	if (err)
		return err;

	err = kvs_begin_xact(&repo->depot, NULL, &xact, 0);
	if (err)
		goto close_depot;

	err = nwif_iface_conf_open_table(&repo->ifaces, &repo->depot, &xact);
	if (err)
		goto rollback;

	err = kvs_commit_xact(&xact);
	if (err)
		goto close_table;
	
	return 0;

rollback:
	kvs_rollback_xact(&xact);

close_table:
	nwif_iface_conf_close_table(&repo->ifaces);

close_depot:
	kvs_close_depot(&repo->depot);

	return err;
}

int
nwif_conf_close(struct nwif_conf_repo *repo)
{
	nwif_assert(repo);

	int ret;

	ret = nwif_iface_conf_close_table(&repo->ifaces);
	if (!ret)
		ret = kvs_close_depot(&repo->depot);
	else
		kvs_close_depot(&repo->depot);

	return ret;
}

struct nwif_conf_repo *
nwif_conf_alloc(void)
{
	return malloc(sizeof(struct nwif_conf_repo));
}

#endif
