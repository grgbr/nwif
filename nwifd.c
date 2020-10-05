#if 0
struct nwif_ether {
	struct nwif_ether_conf  conf;
	struct nwif_iface_state state;
};

static int
nwif_ether_build_apply_request(struct nwif_ether *eif,
                               struct nlmsghdr   *msg,
                               struct nlink_sock *sock)
{
	int                      ret;
	const char              *name;
	const struct ether_addr *addr;
	uint32_t                 mtu;
	uint8_t                  oper;

	nlink_iface_setup_msg(msg,
	                      sock,
	                      ARPHRD_ETHER,
	                      nwif_iface_state_get_id(&eif->state));

	name = nwif_ether_conf_get_name(&eif->conf);
	if (name) {
		ret = nlink_iface_setup_msg_name(msg, name, strlen(name));
		if (ret)
			return ret;
	}

	addr = nwif_ether_conf_get_addr(&eif->conf);
	if (addr) {
		ret = nlink_iface_setup_msg_addr(msg, addr);
		if (ret)
			return ret;
	}

	ret = nwif_ether_conf_get_mtu(&eif->conf, &mtu);
	if (!ret) {
		ret = nlink_iface_setup_msg_mtu(msg, mtu);
		if (ret)
			return ret;
	}
	else if (ret != -ENODATA)
		return ret;

	ret = nwif_ether_conf_get_oper_state(&eif->conf, &oper);
	if (!ret) {
		ret = nlink_iface_setup_msg_oper_state(msg, oper);
		if (ret)
			return ret;
	}
	else if (ret != -ENODATA)
		return ret;

	return 0;
}

static int
nwif_ether_parse_apply_reply(const struct nlmsghdr *msg)
{
	int err;

	err = nlink_parse_msg_head(msg);

	return (err == -ENODATA) ? 0 : err;
}

struct nwif_ether *
nwif_ether_create_from_conf(const struct nwif_iface_conf *conf)
{
	struct nwif_ether            *eif;
	const struct nwif_ether_conf *econf = (struct nwif_ether_conf *)conf;
	int                           err;

	eif = malloc(sizeof(*eif));
	if (!eif) {
		errno = ENOMEM;
		return NULL;
	}

	eif->conf = *econf;

	err = nwif_iface_probe_id(conf->sys_path);
	if (err < 0)
		goto free;

	nwif_iface_state_init(&eif->state, err);

	return eif;

free:
	free(eif);

	errno = -err;
	return NULL;
}

////////////////////////////////////////////////////////////////////////////////

static const struct nwif_ether_conf eth0 = {
	.super = {
		.attr_mask  = NWIF_NAME_ATTR | NWIF_MTU_ATTR | NWIF_OPER_STATE_ATTR,
		.sys_path   = "platform/10013400.virtio_mmio/virtio0",
		.type       = NWIF_ETHER_IFACE_TYPE,
	},
	.name               = "eth0ext",
	.mtu                = 1500,
	.oper_state         = IF_OPER_DOWN,
};

static const struct nwif_ether_conf eth1 = {
	.super = {
		.attr_mask  = NWIF_NAME_ATTR | NWIF_MTU_ATTR | NWIF_OPER_STATE_ATTR,
		.sys_path   = "platform/10013600.virtio_mmio/virtio1",
		.type       = NWIF_ETHER_IFACE_TYPE,
	},
	.name               = "eth1int",
	.mtu                = 4000,
	.oper_state         = IF_OPER_DOWN,
};


struct nwif_iface_conf_store {
	struct nwif_iface_conf * ifaces[2];
};

static const struct nwif_iface_conf_store iface_conf_store = {
	.ifaces = {
		(struct nwif_iface_conf *)&eth0,
		(struct nwif_iface_conf *)&eth1
	}
};

unsigned int
nwif_iface_conf_store_count(const struct nwif_iface_conf_store *store)
{
	return 2;
}

struct nwif_iface_conf_iter {
	unsigned int curr;
};

struct nwif_iface_conf *
nwif_iface_conf_iter_begin(struct nwif_iface_conf_iter        *iter,
                           const struct nwif_iface_conf_store *store)
{
	iter->curr = 1;

	return store->ifaces[0];
}

struct nwif_iface_conf *
nwif_iface_conf_iter_next(struct nwif_iface_conf_iter        *iter,
                          const struct nwif_iface_conf_store *store)
{
	if (iter->curr >= 2)
		return NULL;

	return store->ifaces[iter->curr++];
}

///////////////////////////////////////////////////////////////////////////////

#include <utils/thread.h>

static int
nwif_send_msg_sync(const struct nlink_sock *sock, const struct nlmsghdr *msg)
{
	nwif_assert(sock);
	nwif_assert(msg);

	int ret;

	do {
		ret = nlink_send_msg(sock, msg);
		if (ret == -EAGAIN)
			uthr_yield();
	} while ((ret == -EAGAIN) || (ret == -EINTR));

	return ret;
}

static ssize_t
nwif_recv_msg_sync(const struct nlink_sock *sock, struct nlmsghdr *msg)
{
	nwif_assert(sock);
	nwif_assert(msg);

	ssize_t ret;

	do {
		ret = nlink_recv_msg(sock, msg);

		if (ret == -EAGAIN)
			uthr_yield();
	} while ((ret == -EAGAIN) || (ret == -EINTR));

	nwif_assert(ret);

	return ret;
}

struct nwif_ether_xfer {
	struct nwif_ether *eif;
	uint32_t           seqno;
};

static int
nwif_iface_apply_conf(const struct nwif_iface_conf_store *store,
                      struct nlink_sock                  *sock,
                      struct nlmsghdr                    *msg)
{
	struct nwif_iface_conf_iter  iter;
	struct nwif_iface_conf      *conf;
	int                          ret;
	unsigned int                 cnt;
	struct nwif_ether_xfer      *xfers;
	unsigned int                 x = 0;

	cnt = nwif_iface_conf_store_count(store);
	if (!cnt)
		return -ENOENT;

	xfers = malloc(cnt * sizeof(*xfers));
	if (!xfers)
		return -errno;

	for (conf = nwif_iface_conf_iter_begin(&iter, store);
	     conf;
	     conf = nwif_iface_conf_iter_next(&iter, store)) {
		struct nwif_ether *eif;

		eif = nwif_ether_create_from_conf(conf);
		if (!eif) {
			printf("failed to create ether interface: %s\n",
			       strerror(errno));
			continue;
		}

#warning register iface to repository !!

		ret = nwif_ether_build_apply_request(eif, msg, sock);
		if (ret) {
			printf("failed to build ether interface config request: %s\n",
			       strerror(-ret));
			free(eif);
			continue;
		}

		ret = nwif_send_msg_sync(sock, msg);
		if (ret) {
			printf("failed to transmit ether interface config request: %s\n",
			       strerror(-ret));
			free(eif);
			uthr_yield();
			continue;
		}

		xfers[x].eif = eif;
		xfers[x].seqno = msg->nlmsg_seq;
		x++;
	}

	if (!x) {
		ret = -ENODEV;
		goto free;
	}

	cnt = x;

	do {
		unsigned int c;

		ret = nwif_recv_msg_sync(sock, msg);
		if (ret < 0) {
			printf("failed to fetch ether interface config reply: %s\n",
			       strerror(-ret));
			uthr_yield();
			continue;
		}

		for (c = 0; c < cnt; c++) {
			if (xfers[c].eif && (xfers[c].seqno == msg->nlmsg_seq))
				break;
		}
		if (c == cnt) {
			printf("unexpected ether interface config reply\n");
			continue;
		}

		ret = nwif_ether_parse_apply_reply(msg);
		if (ret)
			printf("ether interface config reply parsing failed: %s\n",
			       strerror(-ret));

		xfers[c].eif = NULL;
	} while (--x);

free:
	free(xfers);

#warning destroy iface repository !!
	return ret;
}

int
main(int argc, char * const argv[])
{
	int                           ret;
	struct nlink_sock             sock;
	struct nlmsghdr              *msg;

	ret = nlink_open_sock(&sock, NETLINK_ROUTE, 0);
	if (ret)
		goto out;

	msg = nlink_alloc_msg();
	if (!msg) {
		ret = -ENOMEM;
		goto close;
	}

	ret = nwif_iface_apply_conf(&iface_conf_store, &sock, msg);

	nlink_free_msg(msg);

close:
	nlink_close_sock(&sock);

out:
	if (ret) {
		printf("error: %s\n", strerror(-ret));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
#endif

#include <nwif/nwif.h>
#include "common.h"
#include "conf_priv.h"
#include "state_priv.h"
#include "iface_priv.h"
#include <clui/clui.h>
#include <utils/path.h>
#include <utils/thread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

struct nwifd_clui_ctx {
	const char *path;
};

#define NWIFD_CLUI_HELP \
	"Usage:\n" \
	"    %1$s -- nwif manager service.\n" \
	"\n" \
	"Synopsis:\n" \
	"    %1$s [OPTIONS]\n" \
	"    Run nwif manager service.\n" \
	"\n" \
	"With [OPTIONS]:\n" \
	"    -d | --dbdir <DBDIR_PATH> use DBDIR_PATH as pathname to configuration\n" \
	"                              database directory.\n" \
	"    -h | --help               this help message.\n"

static int
nwifd_clui_parse_dbdir(const struct clui_opt    *opt,
                       const struct clui_parser *parser,
                       const char               *arg,
                       void                     *ctx)
{
	nwif_assert(opt);
	nwif_assert(parser);
	nwif_assert(arg);
	nwif_assert(ctx);

	if (upath_validate_path_name(arg) > 0) {
		((struct nwifd_clui_ctx *)ctx)->path = arg;

		return 0;
	}

	clui_err(parser,
	         "invalid configuration database path '%.*s'.",
	         PATH_MAX,
	         arg);

	return -ENOENT;
}

static void
nwifd_clui_opts_help(const struct clui_parser *parser,
                     FILE                     *stdio)
{
	fprintf(stdio, NWIFD_CLUI_HELP, parser->argv0);
}

static int
nwifd_clui_parse_help(const struct clui_opt    *opt __unused,
                      const struct clui_parser *parser,
                      const char               *arg __unused,
                      void                     *ctx __unused)
{
	nwif_assert(parser);

	nwifd_clui_opts_help(parser, stdout);

	return -ENOEXEC;
}

static const struct clui_opt nwifd_clui_opts[] = {
	{
		.short_char = 'd',
		.long_name  = "dbdir",
		.has_arg    = CLUI_OPT_REQUIRED_ARG,
		.parse      = nwifd_clui_parse_dbdir
	},
	{
		.short_char = 'h',
		.long_name  = "help",
		.has_arg    = CLUI_OPT_NONE_ARG,
		.parse      = nwifd_clui_parse_help
	}
};

static const struct clui_opt_set nwifd_clui_opt_set = {
	.nr    = array_nr(nwifd_clui_opts),
	.opts  = nwifd_clui_opts,
	.check = NULL,
	.help  = nwifd_clui_opts_help
};

struct nwifd_repo {
	struct kvs_repo         *conf;
	struct nwif_state_sock   sock;
	struct nwif_iface_cache  ifaces;
};

static int
nwifd_process_events(struct nwifd_repo *repo)
{
	int err;

	while (true) {
		err = nwif_state_process_events(&repo->sock);
		if (err != -EAGAIN)
			break;

		uthr_yield();
	}

	return err;
}

static int
nwifd_load(struct nwifd_repo *repo)
{
	int                err;
	struct kvs_xact    xact;
	struct nwif_iface *iface;

	err = nwif_state_start_load(&repo->sock);
	if (err)
		return err;

	err = nwifd_process_events(repo);
	if (err)
		goto clear;

	err = nwif_conf_begin_xact(repo->conf, NULL, &xact, 0);
	if (err)
		goto clear;

	for (iface = nwif_iface_cache_get_first(&repo->ifaces);
	     iface;
	     iface = nwif_iface_cache_get_next(iface)) {
		err = nwif_iface_load(iface, repo->conf, &xact);
		if (err == -ENOENT) {
			/*
			 * No configuration found for this interface: leave it
			 * as-is.
			 */
			err = 0;
			continue;
		}

		if (!err)
			err = nwif_iface_start_apply(iface);

		if (err < 0) {
			/*
			 * Something bad happened: put interface down and
			 * proceed to next one.
			 * TODO: warn / log
			 */
			nwif_iface_conf_set_admin_state(
				nwif_iface_get_conf(iface), IF_OPER_DOWN);
			nwif_iface_start_apply(iface);
		}
	}

	err = nwifd_process_events(repo);

	kvs_end_xact(&xact, err);

	if (!err)
		return 0;

	nwif_state_cancel(&repo->sock);

clear:
	nwif_iface_cache_clear(&repo->ifaces);

	return err;
}

static int
nwifd_handle_iface_event(struct nwif_state_sock   *sock,
                         const struct nlink_iface *attrs,
                         void                     *data)
{
	struct nwifd_repo  *repo = (struct nwifd_repo *)data;
	struct nwif_iface  *iface;
	struct pavl_scan    scan;

	iface = nwif_iface_cache_scan_byid(&repo->ifaces, attrs->index, &scan);
	if (!iface) {
		iface = nwif_iface_create(sock, attrs);
		if (!iface) {
			if (errno == ENOTSUP)
				return 0;
			return -errno;
		}

		nwif_iface_cache_append(&repo->ifaces, &scan, iface);
	}
	else {
		nwif_iface_state_update(iface->state, attrs);
	}

	return 0;
}

static const struct nwif_state_ops nwifd_state_ops = {
	.handle_iface_event = nwifd_handle_iface_event
};

static int
nwifd_open(struct nwifd_repo *repo, const char *path)
{
	int err;

	repo->conf = nwif_conf_create();
	if (!repo->conf)
		return -errno;

	err = nwif_conf_open(repo->conf, path, 0, S_IRUSR | S_IWUSR);
	if (err)
		goto destroy;

	err = nwif_state_open(&repo->sock, &nwifd_state_ops, repo);
	if (err)
		goto close;

	nwif_iface_cache_init(&repo->ifaces);

	return 0;

close:
	nwif_conf_close(repo->conf);

destroy:
	nwif_conf_destroy(repo->conf);

	return err;
}

static int
nwifd_close(struct nwifd_repo *repo)
{
	int err;

	nwif_state_close(&repo->sock);

	nwif_iface_cache_fini(&repo->ifaces);

	err = nwif_conf_close(repo->conf);
	nwif_conf_destroy(repo->conf);

	return err;
}

int
main(int argc, char * const argv[])
{
	struct clui_parser       parser;
	struct nwifd_clui_ctx    ctx = { 0, };
	struct nwifd_repo        repo;
	int                      ret;

	ret = clui_init(&parser, argc, argv);
	if (ret)
		return EXIT_FAILURE;

	ctx.path = CONFIG_NWIF_LOCALSTATEDIR;

	ret = clui_parse_opts(&nwifd_clui_opt_set, &parser, argc, argv, &ctx);
	if (ret < 0) {
		if (ret == -ENOEXEC)
			/* User requested to display help message. */
			return EXIT_SUCCESS;
		return EXIT_FAILURE;
	}

	ret = nwifd_open(&repo, ctx.path);
	if (ret)
		return EXIT_FAILURE;

	ret = nwifd_load(&repo);

	if (!ret)
		ret = nwifd_close(&repo);
	else
		nwifd_close(&repo);

	return !ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
