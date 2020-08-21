#include "common.h"
#include <nwif/conf.h>
#include <stdlib.h>
#include <sys/stat.h>

/* Restrict maximum transaction log file size to 512kB. */
#define NWIF_CONF_MAX_LOG_SIZE (512 << 10)

const char *
nwif_conf_strerror(int err)
{
	return kvs_strerror(err);
}

int
nwif_conf_begin_xact(const struct nwif_conf_repo *repo,
                     const struct kvs_xact       *parent,
                     struct kvs_xact             *xact,
                     unsigned int                 flags)
{
	return kvs_begin_xact(&repo->depot, parent, xact, flags);
}

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

	err = nwif_iface_conf_open(&repo->iface, &repo->depot, &xact);
	if (err)
		goto rollback;

	err = kvs_commit_xact(&xact);
	if (err)
		goto close_depot;
	
	return 0;

rollback:
	kvs_rollback_xact(&xact);

close_depot:
	kvs_close_depot(&repo->depot);

	return err;
}

int
nwif_conf_close(const struct nwif_conf_repo *repo)
{
	nwif_assert(repo);

	int ret;

	ret = nwif_iface_conf_close(&repo->iface);

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
