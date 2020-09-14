#include "nwif/config.h"
#include "ui.h"
#include <nwif/conf.h>
#include <utils/net.h>
#include <utils/path.h>
#include <clui/clui.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define NWIF_CONF_DIR_PATH CONFIG_NWIF_LOCALSTATEDIR

#define nwif_conf_clui_err(_parser, _error, _format, ...) \
	clui_err(_parser, \
	         _format ": %s (%d).", \
	         ## __VA_ARGS__, \
	         nwif_conf_strerror(_error), \
	         _error)

/******************************************************************************
 * Command line parsing context utils
 ******************************************************************************/

struct nwif_conf_clui_ctx;

typedef int (nwif_conf_clui_exec_fn)
            (const struct nwif_conf_clui_ctx *ctx,
             const struct clui_parser        *parser);

struct nwif_iface_conf_attrs {
	unsigned int       mask;
	const char        *name;
	uint8_t            oper_state;
	uint32_t           mtu;
	char              *syspath;
	struct ether_addr  hwaddr;
};

struct nwif_conf_clui_ctx {
	nwif_conf_clui_exec_fn               *exec;
	const char                           *path;
	union {
		const struct clui_cmd        *cmd;
		uint64_t                      iface_id;
		const char                   *iface_name;
	};
	struct nwif_iface_conf_attrs          iface_attrs;
};

static void
nwif_conf_clui_sched_exec(void *ctx, nwif_conf_clui_exec_fn *exec)
{
	nwif_ui_assert(ctx);
	nwif_ui_assert(exec);
	nwif_ui_assert(!((struct nwif_conf_clui_ctx *)ctx)->exec);

	((struct nwif_conf_clui_ctx *)ctx)->exec = exec;
}

static int
nwif_conf_clui_exec_help(const struct nwif_conf_clui_ctx *ctx,
                         const struct clui_parser        *parser)
{
	nwif_ui_assert(ctx);

	clui_help_cmd(ctx->cmd, parser, stdout);

	return 0;
}

static void
nwif_conf_clui_sched_help(void *ctx, const struct clui_cmd *cmd)
{
	nwif_ui_assert(ctx);

	((struct nwif_conf_clui_ctx *)ctx)->cmd = cmd;

	nwif_conf_clui_sched_exec(ctx, nwif_conf_clui_exec_help);
}

/******************************************************************************
 * Configuration clui session management
 ******************************************************************************/

struct nwif_conf_clui_session {
	int                       err;
	struct kvs_xact           xact;
	struct nwif_conf_repo    *repo;
	const struct clui_parser *parser;
};

#define nwif_ui_assert_session(_sess) \
	nwif_ui_assert(_sess); \
	nwif_ui_assert((_sess)->repo); \
	nwif_ui_assert((_sess)->parser)

static int
nwif_conf_begin_clui_session(struct nwif_conf_clui_session *session,
                             const char                    *path,
                             const struct clui_parser      *parser)
{
	nwif_ui_assert(session);
	nwif_ui_assert(upath_validate_path_name(path) > 0);
	nwif_ui_assert(parser);
	int err;

	session->repo = nwif_conf_alloc();
	if (!session->repo)
		return -errno;

	err = nwif_conf_open(session->repo, path, 0, S_IRUSR | S_IWUSR);
	if (err) {
		nwif_conf_clui_err(parser,
		                   err,
		                   "failed to open configuration database '%s'",
		                   path);
		goto free;
	}

	err = nwif_conf_begin_xact(session->repo, NULL, &session->xact, 0);
	if (err) {
		nwif_conf_clui_err(parser,
		                   err,
		                   "failed to start configuration transaction");
		goto close;
	}

	session->err = 0;
	session->parser = parser;

	return 0;

close:
	if (err != -ENOTRECOVERABLE)
		nwif_conf_close(session->repo);

free:
	free(session->repo);

	return err;
}

static int
nwif_conf_close_clui_session(const struct nwif_conf_clui_session *session)
{
	nwif_ui_assert_session(session);

	int err = session->err;

	if (!err) {
		err = nwif_conf_commit_xact(&session->xact);
		if (err) {
			nwif_conf_clui_err(
				session->parser,
				err,
				"failed to commit configuration transaction");

			if (err != -ENOTRECOVERABLE)
				nwif_conf_close(session->repo);

			goto free;
		}

		err = nwif_conf_close(session->repo);
		if (err)
			nwif_conf_clui_err(
				session->parser,
				err,
				"failed to close configuration");
	}
	else {
		if (err == -ENOTRECOVERABLE)
			goto free;

		if (nwif_conf_rollback_xact(&session->xact) == -ENOTRECOVERABLE)
			goto free;

		nwif_conf_close(session->repo);
	}

free:
	free(session->repo);

	return err;
}

/******************************************************************************
 * Base interface handling
 ******************************************************************************/

#define NWIF_CONF_CLUI_IFACE_ID_WHERE \
	"    <IFACE_ID>   -- interface identifier.\n"

#define NWIF_CONF_CLUI_IFACE_NAME_WHERE \
	"    <IFACE_NAME> -- interface name.\n"

enum nwif_conf_clui_iface_col_id {
	NWIF_CONF_CLUI_IFACE_ID_CID,
	NWIF_CONF_CLUI_IFACE_TYPE_CID,
	NWIF_CONF_CLUI_IFACE_NAME_CID,
	NWIF_CONF_CLUI_IFACE_OPER_STATE_CID,
	NWIF_CONF_CLUI_IFACE_MTU_CID,
	NWIF_CONF_CLUI_IFACE_SYSPATH_CID,
	NWIF_CONF_CLUI_IFACE_HWADDR_CID,
	NWIF_CONF_CLUI_IFACE_CID_NR
};

static int
nwif_conf_clui_parse_iface_name(const struct clui_cmd *cmd,
                                struct clui_parser    *parser,
                                const char            *arg,
                                void                  *ctx)
{
	nwif_ui_assert(cmd);
	nwif_ui_assert(parser);
	nwif_ui_assert(arg);
	nwif_ui_assert(ctx);

	ssize_t                       len;
	struct nwif_iface_conf_attrs *attrs = &((struct nwif_conf_clui_ctx *)
	                                        ctx)->iface_attrs;

	len = nwif_ui_parse_iface_name(arg);
	if (len < 0) {
		nwif_conf_clui_err(parser,
		                   len,
		                   "invalid interface name '%.*s' requested",
		                   IFNAMSIZ,
		                   arg);
		return len;
	}

	attrs->name = arg;
	attrs->mask |= NWIF_NAME_ATTR;

	return 0;
}

static const struct clui_kword_parm nwif_conf_clui_iface_name_parm = {
	.kword = "name",
	.parse = nwif_conf_clui_parse_iface_name
};

static int
nwif_conf_clui_parse_iface_oper_state(const struct clui_cmd *cmd,
                                      struct clui_parser    *parser,
                                      const char            *arg,
                                      void                  *ctx)
{
	nwif_ui_assert(cmd);
	nwif_ui_assert(parser);
	nwif_ui_assert(arg);
	nwif_ui_assert(ctx);

	int                           err;
	const char                   *reason;
	struct nwif_iface_conf_attrs *attrs = &((struct nwif_conf_clui_ctx *)
	                                        ctx)->iface_attrs;

	err = nwif_ui_parse_oper_state(arg, &attrs->oper_state);
	switch (err) {
	case 0:
		attrs->mask |= NWIF_OPER_STATE_ATTR;
		return 0;

	case -ENOENT:
		reason = "state unknown";
		break;

	case -EPERM:
		reason = "state not allowed";
		break;

	default:
		err = -EIO;
		reason = "unknown failure";
		break;
	}

	clui_err(parser,
	         "invalid interface operational state '%.5s' requested: %s.",
	         arg,
	         reason);

	return err;
}

static const struct clui_kword_parm nwif_conf_clui_iface_oper_state_parm = {
	.kword = "oper",
	.parse = nwif_conf_clui_parse_iface_oper_state
};

static int
nwif_conf_clui_parse_iface_mtu(const struct clui_cmd *cmd,
                               struct clui_parser    *parser,
                               const char            *arg,
                               void                  *ctx)
{
	nwif_ui_assert(cmd);
	nwif_ui_assert(parser);
	nwif_ui_assert(arg);
	nwif_ui_assert(ctx);

	int                           err;
	struct nwif_iface_conf_attrs *attrs = &((struct nwif_conf_clui_ctx *)
	                                        ctx)->iface_attrs;

	err = nwif_ui_parse_mtu(arg, &attrs->mtu);
	if (!err) {
		attrs->mask |= NWIF_MTU_ATTR;
		return 0;
	}

	clui_err(parser,
	         "invalid interface mtu '%.5s': "
	         "[0:" USTRINGIFY(IP_MAXPACKET) "] integer expected.",
	         arg);

	return err;
}

static const struct clui_kword_parm nwif_conf_clui_iface_mtu_parm = {
	.kword = "mtu",
	.parse = nwif_conf_clui_parse_iface_mtu
};

static int
nwif_conf_clui_parse_iface_syspath(const struct clui_cmd *cmd,
                                   struct clui_parser    *parser,
                                   const char            *arg,
                                   void                  *ctx)
{
	nwif_ui_assert(cmd);
	nwif_ui_assert(parser);
	nwif_ui_assert(arg);
	nwif_ui_assert(ctx);

	ssize_t                       ret;
	const char                   *reason;
	struct nwif_iface_conf_attrs *attrs = &((struct nwif_conf_clui_ctx *)
	                                        ctx)->iface_attrs;

	ret = nwif_ui_normalize_syspath(arg, &attrs->syspath);
	if (ret > 0) {
		attrs->mask |= NWIF_SYSPATH_ATTR;
		return 0;
	}

	switch (ret) {
	case -ENOENT:
		reason = "not a sysfs device path";
		break;

	case -ENAMETOOLONG:
		reason = "pathname too long";
		break;

	case -ENOMEM:
		return -ENOMEM;

	default:
		ret = -EIO;
		reason = "unknown failure";
		break;
	}

	clui_err(parser,
	         "invalid sysfs network device path '%.*s': %s.",
	         UNET_IFACE_SYSPATH_MAX,
	         arg,
	         reason);

	return ret;
}

static const struct clui_kword_parm nwif_conf_clui_iface_syspath_parm = {
	.kword = "syspath",
	.parse = nwif_conf_clui_parse_iface_syspath
};

static int
nwif_conf_clui_parse_iface_hwaddr(const struct clui_cmd *cmd,
                                  struct clui_parser    *parser,
                                  const char            *arg,
                                  void                  *ctx)
{
	nwif_ui_assert(cmd);
	nwif_ui_assert(parser);
	nwif_ui_assert(arg);
	nwif_ui_assert(ctx);

	int                           err;
	const char                   *reason;
	struct nwif_iface_conf_attrs *attrs = &((struct nwif_conf_clui_ctx *)
	                                        ctx)->iface_attrs;

	err = nwif_ui_parse_hwaddr(arg, &attrs->hwaddr);
	switch (err) {
	case 0:
		attrs->mask |= NWIF_HWADDR_ATTR;
		return 0;

	case -EINVAL:
		reason = "invalid hardware address '%.*s': bad EUI-48 format.";
		break;

	case -EPERM:
		reason = "invalid hardware address '%.*s': "
		         "not locally administered and/or unicast.";
		break;

	default:
		err = -EIO;
		reason = "invalid hardware address '%.*s': unknown failure";
	}

	clui_err(parser, reason, UNET_HWADDR_STRING_MAX - 1, arg);

	return err;
}

static const struct clui_kword_parm nwif_conf_clui_iface_hwaddr_parm = {
	.kword = "hwaddr",
	.parse = nwif_conf_clui_parse_iface_hwaddr
};

/******************************************************************************
 * Ethernet interface handling
 ******************************************************************************/

#if defined(CONFIG_NWIF_ETHER)

#include <nwif/ether.h>

#define NWIF_CONF_CLUI_IFACE_NEW_ETHER_SYNOPSIS \
	"    %1$s iface new ether <ETHER_NEW_SPEC> | help\n" \
	"    Create a new ethernet interface.\n" \
	"\n"

#define NWIF_CONF_CLUI_IFACE_NEW_ETHER_WHERE \
	"    <ETHER_NEW_SPEC> -- mandatory new ethernet interface specification.\n"

#define NWIF_CONF_CLUI_NEW_ETHER_HELP \
	"Synopsis:\n" \
	"    %1$s iface new ether <SYSPATH> [NAME_SPEC] [OPER_SPEC] [MTU_SPEC] [HWADDR_SPEC]\n" \
	"    Create a new ethernet interface.\n" \
	"\n" \
	"    %1$s iface new ether help\n" \
	"    This help message.\n" \
	"\n" \
	"With:\n" \
	"    NAME_SPEC   := name <IFACE_NAME>\n" \
	"    OPER_SPEC   := oper <IFACE_OPER>\n" \
	"    IFACE_OPER  := up|down\n" \
	"    MTU_SPEC    := mtu <IFACE_MTU>\n" \
	"    HWADDR_SPEC := hwaddr <IFACE_HWADDR>\n" \
	"\n" \
	"Where:\n" \
	"    <SYSPATH>      -- sysfs network interface path, a non empty string.\n" \
	"    <IFACE_NAME>   -- interface name, a non empty string.\n" \
	"    <IFACE_OPER>   -- interface required operational state.\n" \
	"    <IFACE_MTU>    -- maximum transfer unit in bytes,\n" \
	"                      integer [0:" USTRINGIFY(IP_MAXPACKET) "].\n" \
	"    <IFACE_HWADDR> -- unicast 48-bit MAC address, standard hexadecimal\n" \
	"                      digits and colons notation.\n"

static const struct clui_kword_parm * const nwif_ether_conf_option_parms[] = {
	&nwif_conf_clui_iface_name_parm,
	&nwif_conf_clui_iface_oper_state_parm,
	&nwif_conf_clui_iface_mtu_parm,
	&nwif_conf_clui_iface_hwaddr_parm
};

static int
nwif_conf_clui_fill_ether(struct nwif_ether_conf             *conf,
                          const struct nwif_iface_conf_attrs *attrs)
{
	nwif_ui_assert(conf);
	nwif_ui_assert(attrs);

	if (attrs->mask & ~(NWIF_NAME_ATTR | NWIF_OPER_STATE_ATTR |
	                    NWIF_MTU_ATTR | NWIF_SYSPATH_ATTR |
	                    NWIF_HWADDR_ATTR))
		return -ENOTSUP;

	if (attrs->mask & NWIF_NAME_ATTR)
		nwif_iface_conf_set_name(nwif_ether_conf_to_iface(conf),
		                         attrs->name,
		                         strlen(attrs->name));

	if (attrs->mask & NWIF_OPER_STATE_ATTR)
		nwif_iface_conf_set_oper_state(nwif_ether_conf_to_iface(conf),
		                               attrs->oper_state);

	if (attrs->mask & NWIF_MTU_ATTR)
		nwif_iface_conf_set_oper_state(nwif_ether_conf_to_iface(conf),
		                               attrs->mtu);

	if (attrs->mask & NWIF_SYSPATH_ATTR)
		nwif_ether_conf_set_syspath(conf,
		                            attrs->syspath,
		                            strlen(attrs->syspath));

	if (attrs->mask & NWIF_HWADDR_ATTR)
		nwif_ether_conf_set_hwaddr(conf, &attrs->hwaddr);

	return 0;
}

static int
nwif_conf_clui_exec_new_ether(const struct nwif_conf_clui_ctx *ctx,
                              const struct clui_parser        *parser)
{
	nwif_ui_assert(ctx);

	struct nwif_ether_conf        *conf;
	struct nwif_conf_clui_session  sess;
	int                            ret;

	conf = nwif_ether_conf_create();
	if (!conf) {
		ret = -errno;
		nwif_conf_clui_err(
			parser,
			ret,
			"failed to allocate interface");
		goto free;
	}

	ret = nwif_conf_clui_fill_ether(conf, &ctx->iface_attrs);
	if (ret) {
		clui_err(parser,
		         "failed to create ethernet interface: "
		         "unexpected attributes set.");
		goto destroy;
	}

	ret = nwif_conf_begin_clui_session(&sess, ctx->path, parser);
	if (ret)
		goto destroy;

	sess.err = nwif_iface_conf_save(nwif_ether_conf_to_iface(conf),
	                                &sess.xact,
	                                sess.repo);
	if (sess.err)
		nwif_conf_clui_err(parser,
		                   sess.err,
		                   "failed to create ethernet interface");

	ret = nwif_conf_close_clui_session(&sess);

destroy:
	nwif_iface_conf_destroy(nwif_ether_conf_to_iface(conf));

free:
	free(ctx->iface_attrs.syspath);

	return ret;
}

static int
nwif_conf_clui_parse_new_ether(const struct clui_cmd *cmd,
                               struct clui_parser    *parser,
                               int                    argc,
                               char * const           argv[],
                               void                  *ctx)
{
	nwif_ui_assert(ctx);

	int ret;

	if (argc < 1 || argc > 9) {
		clui_err(parser, "invalid number of arguments.\n");
		goto help;
	}

	if (!strcmp(argv[0], "help")) {
		nwif_conf_clui_sched_help(ctx, cmd);
		return 0;
	}

	ret = nwif_conf_clui_parse_iface_syspath(cmd, parser, argv[0], ctx);
	if (ret)
		return ret;

	if (argc > 1) {
		ret = clui_parse_all_kword_parms(
			cmd,
			parser,
			nwif_ether_conf_option_parms,
			array_nr(nwif_ether_conf_option_parms),
			argc - 1,
			&argv[1],
			ctx);
		if (ret)
			goto free;
	}

	nwif_conf_clui_sched_exec(ctx, nwif_conf_clui_exec_new_ether);

	return 0;

free:
	free(((struct nwif_conf_clui_ctx *)ctx)->iface_attrs.syspath);

	return ret;

help:
	clui_help_cmd(cmd, parser, stderr);

	return -EINVAL;
}

static void
nwif_conf_clui_new_ether_help(const struct clui_cmd    *cmd __unused,
                              const struct clui_parser *parser,
                              FILE                     *stdio)
{
	fprintf(stdio, NWIF_CONF_CLUI_NEW_ETHER_HELP, parser->argv0);
}

static const struct clui_cmd nwif_conf_clui_new_ether_cmd = {
	.parse = nwif_conf_clui_parse_new_ether,
	.help  = nwif_conf_clui_new_ether_help
};

#else /* !defined(CONFIG_NWIF_ETHER) */

#define NWIF_CONF_CLUI_IFACE_NEW_ETHER_SYNOPSIS
#define NWIF_CONF_CLUI_IFACE_NEW_ETHER_WHERE

#endif /* defined(CONFIG_NWIF_ETHER) */

/******************************************************************************
 * iface new command handling
 ******************************************************************************/

#define NWIF_CONF_CLUI_IFACE_NEW_HELP \
	"Synopsis:\n" \
	NWIF_CONF_CLUI_IFACE_NEW_ETHER_SYNOPSIS \
	"    %1$s iface new help\n" \
	"    This help message.\n" \
	"\n" \
	"Where:\n" \
	NWIF_CONF_CLUI_IFACE_NEW_ETHER_WHERE

static int
nwif_conf_clui_parse_new_iface(const struct clui_cmd *cmd,
                               struct clui_parser    *parser,
                               int                    argc,
                               char * const           argv[],
                               void                  *ctx)
{
	nwif_ui_assert(ctx);

	if (argc < 1) {
		clui_err(parser, "invalid number of arguments.\n");
		goto help;
	}

	if (!strcmp(argv[0], "help")) {
		nwif_conf_clui_sched_help(ctx, cmd);
		return 0;
	}
#if defined(CONFIG_NWIF_ETHER)
	else if (!strcmp(argv[0], "ether"))
		return clui_parse_cmd(&nwif_conf_clui_new_ether_cmd,
		                      parser,
		                      argc - 1,
		                      &argv[1],
		                      ctx);
#endif /* defined(CONFIG_NWIF_ETHER) */

	clui_err(parser, "unknown '%s' interface type.\n", argv[0]);

help:
	clui_help_cmd(cmd, parser, stderr);

	return -EINVAL;
}

static void
nwif_conf_clui_iface_new_help(const struct clui_cmd    *cmd __unused,
                              const struct clui_parser *parser,
                              FILE                     *stdio)
{
	fprintf(stdio, NWIF_CONF_CLUI_IFACE_NEW_HELP, parser->argv0);
}

static const struct clui_cmd nwif_conf_clui_iface_new_cmd = {
	.parse = nwif_conf_clui_parse_new_iface,
	.help  = nwif_conf_clui_iface_new_help
};

/******************************************************************************
 * iface setup command handling
 ******************************************************************************/

#define NWIF_CONF_CLUI_IFACE_SET_HELP \
	"Synopsis:\n" \
	"    %1$s iface set <IFACE_ID> <ETHER_SET_SPEC>\n" \
	"    %1$s iface set <IFACE_NAME> <ETHER_SET_SPEC>\n" \
	"    Setup attributes of ethernet interface specified by <IFACE_ID> or\n" \
	"    <IFACE_NAME> according to <ETHER_SET_SPEC>.\n" \
	"\n" \
	"    %1$s iface set help\n" \
	"    This help message.\n" \
	"\n" \
	"With:\n" \
	"    ETHER_SET_SPEC := [SYSPATH_SPEC] [NAME_SPEC] [OPER_SPEC] [MTU_SPEC] [HWADDR_SPEC]\n" \
	"    SYSPATH_SPEC   := syspath <SYSPATH>\n" \
	"    NAME_SPEC      := name <IFACE_NAME>\n" \
	"    OPER_SPEC      := oper <IFACE_OPER>\n" \
	"    IFACE_OPER     := up|down\n" \
	"    MTU_SPEC       := mtu <IFACE_MTU>\n" \
	"    HWADDR_SPEC    := hwaddr <IFACE_HWADDR>\n" \
	"\n" \
	"Where:\n" \
	NWIF_CONF_CLUI_IFACE_ID_WHERE \
	NWIF_CONF_CLUI_IFACE_NAME_WHERE \
	"    <SYSPATH>      -- sysfs network interface path, a non empty string.\n" \
	"    <IFACE_NAME>   -- interface name, a non empty string.\n" \
	"    <IFACE_OPER>   -- interface required operational state.\n" \
	"    <IFACE_MTU>    -- maximum transfer unit in bytes,\n" \
	"                      integer [0:" USTRINGIFY(IP_MAXPACKET) "].\n" \
	"    <IFACE_HWADDR> -- unicast 48-bit MAC address, standard hexadecimal\n" \
	"                      digits and colons notation.\n"

static const struct clui_kword_parm * const nwif_iface_conf_option_parms[] = {
	&nwif_conf_clui_iface_syspath_parm,
	&nwif_conf_clui_iface_name_parm,
	&nwif_conf_clui_iface_oper_state_parm,
	&nwif_conf_clui_iface_mtu_parm,
	&nwif_conf_clui_iface_hwaddr_parm
};

static int
nwif_conf_clui_exec_set_iface_byid(const struct nwif_conf_clui_ctx *ctx,
                                   const struct clui_parser        *parser)
{
	nwif_ui_assert(ctx);

	struct nwif_conf_clui_session       sess;
	const struct nwif_iface_conf_attrs *attrs = &ctx->iface_attrs;
	struct nwif_iface_conf             *conf;
	int                                 ret;

	ret = nwif_conf_begin_clui_session(&sess, ctx->path, parser);
	if (ret)
		goto free;

	conf = nwif_iface_conf_create_byid(ctx->iface_id, &sess.xact, sess.repo);
	if (!conf) {
		ret = -errno;
		nwif_conf_clui_err(parser,
		                   ret,
		                   "failed to load '%" PRIx64 "' interface",
		                   ctx->iface_id);
		goto close;
	}

	switch (nwif_iface_conf_get_type(conf)) {
	case NWIF_ETHER_IFACE_TYPE:
		ret = nwif_conf_clui_fill_ether(
			nwif_ether_conf_from_iface(conf), &ctx->iface_attrs);
		if (ret) {
			clui_err(parser,
			         "failed to setup '%" PRIx64 "' ethernet "
			         "interface: unexpected attributes set.",
		                 ctx->iface_id);
		}
		break;

	default:
		nwif_ui_assert(0);
	}

	if (ret)
		goto destroy;

	ret = nwif_iface_conf_save(conf, &sess.xact, sess.repo);
	if (ret)
		nwif_conf_clui_err(parser,
		                   ret,
		                   "failed to save '%" PRIx64 "' interface",
		                   ctx->iface_id);

destroy:
	nwif_iface_conf_destroy(conf);

close:
	sess.err = ret;
	ret = nwif_conf_close_clui_session(&sess);

free:
	if (attrs->mask & NWIF_SYSPATH_ATTR)
		free(attrs->syspath);

	return ret;
}

static int
nwif_conf_clui_exec_set_iface_byname(const struct nwif_conf_clui_ctx *ctx,
                                     const struct clui_parser        *parser)
{
	nwif_ui_assert(ctx);

	struct nwif_conf_clui_session       sess;
	const struct nwif_iface_conf_attrs *attrs = &ctx->iface_attrs;
	struct nwif_iface_conf             *conf;
	int                                 ret;

	ret = nwif_conf_begin_clui_session(&sess, ctx->path, parser);
	if (ret)
		goto free;

	conf = nwif_iface_conf_create_byname(ctx->iface_name,
	                                     strlen(ctx->iface_name),
	                                     &sess.xact,
	                                     sess.repo);
	if (!conf) {
		ret = -errno;
		nwif_conf_clui_err(parser,
		                   ret,
		                   "failed to load '%s' interface",
		                   ctx->iface_name);
		goto close;
	}

	switch (nwif_iface_conf_get_type(conf)) {
	case NWIF_ETHER_IFACE_TYPE:
		ret = nwif_conf_clui_fill_ether(
			nwif_ether_conf_from_iface(conf), &ctx->iface_attrs);
		if (ret) {
			clui_err(parser,
			         "failed to setup '%s' ethernet interface: "
			         "unexpected attributes set.",
			         ctx->iface_name);
		}
		break;

	default:
		nwif_ui_assert(0);
	}

	if (ret)
		goto destroy;

	ret = nwif_iface_conf_save(conf, &sess.xact, sess.repo);
	if (ret)
		nwif_conf_clui_err(parser,
		                   ret,
		                   "failed to save '%s' interface",
		                   ctx->iface_name);


destroy:
	nwif_iface_conf_destroy(conf);

close:
	sess.err = ret;
	ret = nwif_conf_close_clui_session(&sess);

free:
	if (attrs->mask & NWIF_SYSPATH_ATTR)
		free(attrs->syspath);

	return ret;
}

static int
nwif_conf_clui_parse_set_iface(const struct clui_cmd *cmd,
                               struct clui_parser    *parser,
                               int                    argc,
                               char * const           argv[],
                               void                  *ctx)
{
	nwif_ui_assert(ctx);

	struct nwif_conf_clui_ctx    *nctx = (struct nwif_conf_clui_ctx *)ctx;
	struct nwif_iface_conf_attrs *attrs = &nctx->iface_attrs;
	nwif_conf_clui_exec_fn       *exec;
	int                           ret;

	if (argc < 1) {
		clui_err(parser, "missing arguments.\n");
		goto help;
	}

	if (!strcmp(argv[0], "help")) {
		nwif_conf_clui_sched_help(ctx, cmd);
		return 0;
	}

	if (argc < 2 || argc > 11) {
		clui_err(parser, "invalid number of arguments.\n");
		goto help;
	}

	ret = nwif_ui_parse_conf_id(argv[0], &nctx->iface_id);
	if (!ret) {
		exec = nwif_conf_clui_exec_set_iface_byid;
		goto attrs;
	}

	ret = nwif_ui_parse_iface_name(argv[0]);
	if (ret > 0) {
		nctx->iface_name = argv[0];
		exec = nwif_conf_clui_exec_set_iface_byname;
		goto attrs;
	}

	clui_err(parser, "invalid interface name or id '%s'.\n", argv[0]);

	return -EINVAL;

attrs:
	if (argc > 1) {
		ret = clui_parse_all_kword_parms(
			cmd,
			parser,
			nwif_iface_conf_option_parms,
			array_nr(nwif_iface_conf_option_parms),
			argc - 1,
			&argv[1],
			ctx);
		if (ret)
			goto free;
	}

	nwif_conf_clui_sched_exec(ctx, exec);

	return 0;

free:
	if (attrs->mask & NWIF_SYSPATH_ATTR)
		free(attrs->syspath);

	return ret;

help:
	clui_help_cmd(cmd, parser, stderr);

	return -EINVAL;
}

static void
nwif_conf_clui_iface_set_help(const struct clui_cmd    *cmd __unused,
                              const struct clui_parser *parser,
                              FILE                     *stdio)
{
	fprintf(stdio, NWIF_CONF_CLUI_IFACE_SET_HELP, parser->argv0);
}

static const struct clui_cmd nwif_conf_clui_iface_set_cmd = {
	.parse = nwif_conf_clui_parse_set_iface,
	.help  = nwif_conf_clui_iface_set_help
};

/******************************************************************************
 * iface show command handling
 ******************************************************************************/

#define NWIF_CONF_CLUI_IFACE_SHOW_HELP \
	"Synopsis:\n" \
	"    %1$s iface show <IFACE_ID>\n" \
	"    %1$s iface show <IFACE_NAME>\n" \
	"    Show attributes of interface specified by <IFACE_ID> or <IFACE_NAME>.\n" \
	"\n" \
	"    %1$s iface show [all]\n" \
	"    Show attributes of all interfaces.\n" \
	"\n" \
	"    %1$s iface show help\n" \
	"    This help message.\n" \
	"\n" \
	"Where:\n" \
	NWIF_CONF_CLUI_IFACE_ID_WHERE \
	NWIF_CONF_CLUI_IFACE_NAME_WHERE

static int
nwif_conf_clui_show_all_ifaces(struct nwif_conf_clui_session *session)
{
	nwif_ui_assert_session(session);

	struct libscols_table   *tbl;
	struct kvs_iter          iter;
	uint64_t                 id;
        struct kvs_chunk         item;
	int                      err;

	err = nwif_iface_conf_init_iter(session->repo, &session->xact, &iter);
	if (err) {
		nwif_conf_clui_err(
			session->parser,
			err,
			"failed to start browsing interfaces configuration");
		goto err;
	}

	tbl = nwif_ui_create_iface_conf_table();
	if (!tbl) {
		nwif_conf_clui_err(
			session->parser,
			err,
			"failed to create interfaces configuration table");
		goto fini;
	}

	for (err = nwif_iface_conf_iter_first(&iter, &id, &item);
	     !err;
	     err = nwif_iface_conf_iter_next(&iter, &id, &item)) {
		struct nwif_iface_conf *iface;

		iface = nwif_iface_conf_create_from_rec(id, &item);
		if (!iface) {
			err = -errno;
			break;
		}

		err = nwif_ui_render_iface_conf_table(tbl, iface);

		nwif_iface_conf_destroy(iface);
	}

	if (err && (err != -ENOENT)) {
		nwif_conf_clui_err(
			session->parser,
			err,
			"failed to browse interfaces configuration");
		goto destroy;
	}

	nwif_ui_display_iface_conf_table(tbl);

	nwif_ui_destroy_iface_conf_table(tbl);

	err = nwif_iface_conf_fini_iter(&iter);
	if (err) {
		nwif_conf_clui_err(
			session->parser,
			err,
			"failed to stop browsing interfaces configuration");
		goto err;
	}

	return 0;

destroy:
	nwif_ui_destroy_iface_conf_table(tbl);

fini:
	nwif_iface_conf_fini_iter(&iter);

err:
	session->err = err;

	return err;
}

static int
nwif_conf_clui_exec_show_all_ifaces(const struct nwif_conf_clui_ctx *ctx,
                                    const struct clui_parser        *parser)
{
	nwif_ui_assert(ctx);

	struct nwif_conf_clui_session sess;
	int                           err;

	err = nwif_conf_begin_clui_session(&sess, ctx->path, parser);
	if (err)
		return err;

	nwif_conf_clui_show_all_ifaces(&sess);

	return nwif_conf_close_clui_session(&sess);
}

static int
nwif_conf_clui_show_iface(struct nwif_conf_clui_session *session,
                          const struct nwif_iface_conf  *iface)
{
	struct libscols_table *tbl;
	int                    ret;

	tbl = nwif_ui_create_iface_conf_table();
	if (!tbl) {
		ret = -errno;
		nwif_conf_clui_err(
			session->parser,
			ret,
			"failed to create interface configuration table");
		return ret;
	}

	ret = nwif_ui_render_iface_conf_table(tbl, iface);
	if (ret)
		nwif_conf_clui_err(
			session->parser,
			ret,
			"failed to render '%s' interface configuration",
			nwif_iface_conf_get_name(iface));
	else
		nwif_ui_display_iface_conf_table(tbl);

	nwif_ui_destroy_iface_conf_table(tbl);

	return ret;
}

static int
nwif_conf_clui_show_iface_byname(struct nwif_conf_clui_session *session,
                                 const char                    *name)
{
	nwif_ui_assert(unet_check_iface_name(name) > 0);

	struct nwif_iface_conf *iface;
	int                     ret;

	iface = nwif_iface_conf_create_byname(name,
	                                      strlen(name),
	                                      &session->xact,
	                                      session->repo);
	if (!iface) {
		nwif_conf_clui_err(
			session->parser,
			-errno,
			"failed to load '%s' interface configuration",
			name);
		return -errno;
	}

	ret = nwif_conf_clui_show_iface(session, iface);

	nwif_iface_conf_destroy(iface);

	return ret;
}

static int
nwif_conf_clui_exec_show_iface_byname(const struct nwif_conf_clui_ctx *ctx,
                                      const struct clui_parser        *parser)
{
	nwif_ui_assert(ctx);

	struct nwif_conf_clui_session sess;
	int                           err;

	err = nwif_conf_begin_clui_session(&sess, ctx->path, parser);
	if (err)
		return err;

	nwif_conf_clui_show_iface_byname(&sess, ctx->iface_name);

	return nwif_conf_close_clui_session(&sess);
}

static int
nwif_conf_clui_show_iface_byid(struct nwif_conf_clui_session *session,
                               uint64_t                       id)
{
	struct nwif_iface_conf *iface;
	int                     ret;

	iface = nwif_iface_conf_create_byid(id, &session->xact, session->repo);
	if (!iface) {
		char str[NWIF_CONF_ID_STRING_MAX];

		nwif_ui_sprintf_conf_id(str, id);
		nwif_conf_clui_err(session->parser,
		                   -errno,
		                   "failed to show interface identified by "
		                   "'%s'",
		                   str);
		return -errno;
	}

	ret = nwif_conf_clui_show_iface(session, iface);

	nwif_iface_conf_destroy(iface);

	return ret;
}

static int
nwif_conf_clui_exec_show_iface_byid(const struct nwif_conf_clui_ctx *ctx,
                                    const struct clui_parser        *parser)
{
	nwif_ui_assert(ctx);

	struct nwif_conf_clui_session sess;
	int                           err;

	err = nwif_conf_begin_clui_session(&sess, ctx->path, parser);
	if (err)
		return err;

	nwif_conf_clui_show_iface_byid(&sess, ctx->iface_id);

	return nwif_conf_close_clui_session(&sess);
}

static int
nwif_conf_clui_parse_iface_show(const struct clui_cmd *cmd,
                                struct clui_parser    *parser,
                                int                    argc,
                                char * const           argv[],
                                void                  *ctx)
{
	nwif_ui_assert(ctx);

	if (argc == 1) {
		const char                *arg = argv[0];
		struct nwif_conf_clui_ctx *nctx;
		int                        ret;

		if (!strcmp(arg, "help")) {
			nwif_conf_clui_sched_help(ctx, cmd);
			return 0;
		}

		if (!strcmp(arg, "all")) {
			nwif_conf_clui_sched_exec(
				ctx, nwif_conf_clui_exec_show_all_ifaces);
			return 0;
		}

		nctx = (struct nwif_conf_clui_ctx *)ctx;

		ret = nwif_ui_parse_conf_id(arg, &nctx->iface_id);
		if (!ret) {
			nwif_conf_clui_sched_exec(
				ctx, nwif_conf_clui_exec_show_iface_byid);
			return 0;
		}

		ret = nwif_ui_parse_iface_name(arg);
		if (ret > 0) {
			nctx->iface_name = arg;
			nwif_conf_clui_sched_exec(
				ctx, nwif_conf_clui_exec_show_iface_byname);
			return 0;
		}

		clui_err(parser, "invalid interface name or id '%s'.\n", arg);

		return -EINVAL;
	}
	else if (!argc) {
		nwif_conf_clui_sched_exec(ctx,
		                          nwif_conf_clui_exec_show_all_ifaces);
		return 0;
	}
	else
		clui_err(parser, "invalid number of arguments.\n");

	clui_help_cmd(cmd, parser, stderr);

	return -EINVAL;
}

static void
nwif_conf_clui_iface_show_help(const struct clui_cmd    *cmd __unused,
                               const struct clui_parser *parser,
                               FILE                     *stdio)
{
	fprintf(stdio, NWIF_CONF_CLUI_IFACE_SHOW_HELP, parser->argv0);
}

static const struct clui_cmd nwif_conf_clui_iface_show_cmd = {
	.parse = nwif_conf_clui_parse_iface_show,
	.help  = nwif_conf_clui_iface_show_help
};

/******************************************************************************
 * iface del command handling
 ******************************************************************************/

#define NWIF_CONF_CLUI_IFACE_DEL_HELP \
	"Synopsis:\n" \
	"    %1$s iface del <IFACE_ID>\n" \
	"    Delete interface specified by <IFACE_ID>.\n" \
	"\n" \
	"    %1$s iface del <IFACE_NAME>\n" \
	"    Delete interface specified by <IFACE_NAME>.\n" \
	"\n" \
	"    %1$s iface del help\n" \
	"    This help message.\n" \
	"\n" \
	"Where:\n" \
	NWIF_CONF_CLUI_IFACE_ID_WHERE \
	NWIF_CONF_CLUI_IFACE_NAME_WHERE \

static int
nwif_conf_clui_exec_del_iface_byid(const struct nwif_conf_clui_ctx *ctx,
                                   const struct clui_parser        *parser)
{
	nwif_ui_assert(ctx);

	struct nwif_conf_clui_session sess;
	int                           err;

	err = nwif_conf_begin_clui_session(&sess, ctx->path, parser);
	if (err)
		return err;

	err = nwif_iface_conf_del_byid(ctx->iface_id, &sess.xact, sess.repo);
	if (err) {
		char str[NWIF_CONF_ID_STRING_MAX];

		nwif_ui_sprintf_conf_id(str, ctx->iface_id);
		nwif_conf_clui_err(parser,
		                   err,
		                   "failed to delete interface identified by "
		                   "'%s'",
		                   str);
	}

	sess.err = err;

	return nwif_conf_close_clui_session(&sess);
}

static int
nwif_conf_clui_exec_del_iface_byname(const struct nwif_conf_clui_ctx *ctx,
                                     const struct clui_parser        *parser)
{
	nwif_ui_assert(ctx);

	struct nwif_conf_clui_session sess;
	int                           err;

	err = nwif_conf_begin_clui_session(&sess, ctx->path, parser);
	if (err)
		return err;

	err = nwif_iface_conf_del_byname(ctx->iface_name,
	                                 strlen(ctx->iface_name),
	                                 &sess.xact,
	                                 sess.repo);
	if (err) {
		char str[NWIF_CONF_ID_STRING_MAX];

		nwif_ui_sprintf_conf_id(str, ctx->iface_id);
		nwif_conf_clui_err(parser,
		                   err,
		                   "failed to delete interface '%s'",
		                   ctx->iface_name);
	}

	sess.err = err;

	return nwif_conf_close_clui_session(&sess);
}

static int
nwif_conf_clui_parse_del_iface(const struct clui_cmd *cmd,
                               struct clui_parser    *parser,
                               int                    argc,
                               char * const           argv[],
                               void                  *ctx)
{
	nwif_ui_assert(ctx);

	struct nwif_conf_clui_ctx *nctx = (struct nwif_conf_clui_ctx *)ctx;
	const char                *arg = argv[0];
	int                        ret;

	if (argc != 1) {
		clui_err(parser, "invalid number of arguments.\n");
		clui_help_cmd(cmd, parser, stderr);
		return -EINVAL;
	}

	if (!strcmp(arg, "help")) {
		nwif_conf_clui_sched_help(ctx, cmd);
		return 0;
	}

	ret = nwif_ui_parse_conf_id(arg, &nctx->iface_id);
	if (!ret) {
		nwif_conf_clui_sched_exec(ctx,
		                          nwif_conf_clui_exec_del_iface_byid);
		return 0;
	}

	ret = nwif_ui_parse_iface_name(arg);
	if (ret > 0) {
		nctx->iface_name = arg;
		nwif_conf_clui_sched_exec(ctx,
	                                  nwif_conf_clui_exec_del_iface_byname);
		return 0;
	}

	clui_err(parser, "invalid interface name or id '%s'.\n", arg);

	return -EINVAL;
}

static void
nwif_conf_clui_iface_del_help(const struct clui_cmd    *cmd __unused,
                              const struct clui_parser *parser,
                              FILE                     *stdio)
{
	fprintf(stdio, NWIF_CONF_CLUI_IFACE_DEL_HELP, parser->argv0);
}

static const struct clui_cmd nwif_conf_clui_iface_del_cmd = {
	.parse = nwif_conf_clui_parse_del_iface,
	.help  = nwif_conf_clui_iface_del_help
};

/******************************************************************************
 * iface command handling
 ******************************************************************************/

#define NWIF_CONF_CLUI_IFACE_HELP \
	"Synopsis:\n" \
	"    %1$s iface show [IFACE_SHOW_SPEC] | help\n" \
	"    Show attributes of interface according to [IFACE_SHOW_SPEC].\n" \
	"\n" \
	"    %1$s iface new <IFACE_NEW_SPEC> | help\n" \
	"    Create new interface according to <IFACE_NEW_SPEC>.\n" \
	"\n" \
	"    %1$s iface set <IFACE_SET_SPEC> | help\n" \
	"    Setup interface attributes according to <IFACE_SET_SPEC>.\n" \
	"\n" \
	"    %1$s iface del <IFACE_DEL_SPEC> | help\n" \
	"    Delete interface according to <IFACE_DEL_SPEC>.\n" \
	"\n" \
	"    %1$s iface help\n" \
	"    This help message.\n" \
	"\n" \
	"Where:\n" \
	"    [IFACE_SHOW_SPEC] -- optional show interface specification.\n" \
	"    <IFACE_NEW_SPEC>  -- mandatory interface creation specification.\n" \
	"    <IFACE_SET_SPEC>  -- mandatory interface setup specification.\n" \
	"    <IFACE_DEL_SPEC>  -- mandatory interface deletion specification.\n"

static int
nwif_conf_clui_parse_iface(const struct clui_cmd *cmd,
                           struct clui_parser    *parser,
                           int                    argc,
                           char * const           argv[],
                           void                  *ctx)
{
	nwif_ui_assert(ctx);

	if (argc < 1) {
		clui_err(parser, "invalid number of arguments.\n");
		goto help;
	}

	if (!strcmp(argv[0], "show")) {
		return clui_parse_cmd(&nwif_conf_clui_iface_show_cmd,
		                      parser,
		                      argc - 1,
		                      &argv[1],
		                      ctx);
	}
	else if (!strcmp(argv[0], "new")) {
		return clui_parse_cmd(&nwif_conf_clui_iface_new_cmd,
		                      parser,
		                      argc - 1,
		                      &argv[1],
		                      ctx);
	}
	else if (!strcmp(argv[0], "set")) {
		return clui_parse_cmd(&nwif_conf_clui_iface_set_cmd,
		                      parser,
		                      argc - 1,
		                      &argv[1],
		                      ctx);
	}
#if 0
	else if (!strcmp(argv[0], "clear")) {
		return clui_parse_cmd(&nwif_conf_clui_iface_clear_cmd,
		                      parser,
		                      argc - 1,
		                      &argv[1],
		                      ctx);
	}
#endif
	else if (!strcmp(argv[0], "del")) {
		return clui_parse_cmd(&nwif_conf_clui_iface_del_cmd,
		                      parser,
		                      argc - 1,
		                      &argv[1],
		                      ctx);
	}
	else if (!strcmp(argv[0], "help")) {
		nwif_conf_clui_sched_help(ctx, cmd);
		return 0;
	}
	
	clui_err(parser, "unknown '%s' subcommand.\n", argv[0]);

help:
	clui_help_cmd(cmd, parser, stderr);

	return -EINVAL;
}

static void
nwif_conf_clui_iface_help(const struct clui_cmd    *cmd __unused,
                          const struct clui_parser *parser,
                          FILE                     *stdio)
{
	fprintf(stdio, NWIF_CONF_CLUI_IFACE_HELP, parser->argv0);
}

static const struct clui_cmd nwif_conf_clui_iface_cmd = {
	.parse = nwif_conf_clui_parse_iface,
	.help  = nwif_conf_clui_iface_help
};

/******************************************************************************
 * Top-level command
 ******************************************************************************/

#define NWIF_CONF_CLUI_HELP \
	"Usage:\n" \
	"    %1$s -- Manage nwif configuration.\n" \
	"\n" \
	"Synopsis:\n" \
	"    %1$s iface [OPTIONS] <IFACE_CMD> | help\n" \
	"    Perform interface(s) operation according to <IFACE_CMD> command.\n" \
	"\n" \
	"    %1$s help\n" \
	"    This help message.\n" \
	"\n" \
	"With [OPTIONS]:\n" \
	"    -d | --dbdir <DBDIR_PATH> use DBDIR_PATH as pathname to configuration\n" \
	"                              database directory.\n"

static void
nwif_conf_clui_cmd_help(const struct clui_cmd    *cmd __unused,
                        const struct clui_parser *parser,
                        FILE                     *stdio)
{
	fprintf(stdio, NWIF_CONF_CLUI_HELP, parser->argv0);
}

static int
nwif_conf_clui_parse(const struct clui_cmd *cmd,
                     struct clui_parser    *parser,
                     int                    argc,
                     char * const           argv[],
                     void                  *ctx)
{
	nwif_ui_assert(ctx);

	if (argc < 1) {
		clui_err(parser, "missing argument.\n");
		goto help;
	}

	if (!strcmp(argv[0], "iface")) {
		return clui_parse_cmd(&nwif_conf_clui_iface_cmd,
		                      parser,
		                      argc - 1,
		                      &argv[1],
		                      ctx);
	}
	else if (!strcmp(argv[0], "help")) {
		nwif_conf_clui_sched_help(ctx, cmd);
		return 0;
	}
	else
		clui_err(parser, "unknown '%s' subcommand.\n", argv[0]);

help:
	clui_help_cmd(cmd, parser, stderr);

	return -EINVAL;
}

static const struct clui_cmd nwif_conf_clui_cmd = {
	.parse = nwif_conf_clui_parse,
	.help  = nwif_conf_clui_cmd_help
};

static void
nwif_conf_clui_opts_help(const struct clui_parser *parser,
                         FILE                     *stdio)
{
	fprintf(stdio, NWIF_CONF_CLUI_HELP, parser->argv0);
}

static int
nwif_conf_clui_parse_dbdir(const struct clui_opt    *opt,
                           const struct clui_parser *parser,
                           const char               *arg,
                           void                     *ctx)
{
	nwif_ui_assert(opt);
	nwif_ui_assert(parser);
	nwif_ui_assert(arg);
	nwif_ui_assert(ctx);

	if (upath_validate_path_name(arg) > 0) {
		((struct nwif_conf_clui_ctx *)ctx)->path = arg;

		return 0;
	}

	clui_err(parser,
	         "invalid configuration database path '%.*s'.",
	         PATH_MAX,
	         arg);

	return -ENOENT;
}

static const struct clui_opt nwif_conf_clui_opts[] = {
	{
		.short_char = 'd',
		.long_name  = "dbdir",
		.has_arg    = CLUI_OPT_REQUIRED_ARG,
		.parse      = nwif_conf_clui_parse_dbdir
	}
};

static const struct clui_opt_set nwif_conf_clui_opt_set = {
	.nr    = array_nr(nwif_conf_clui_opts),
	.opts  = nwif_conf_clui_opts,
	.check = NULL,
	.help  = nwif_conf_clui_opts_help
};

int
main(int argc, char * const argv[])
{
	struct clui_parser        parser;
	struct nwif_conf_clui_ctx ctx = { 0 };
	int                       err;

	err = clui_init(&parser,
	                &nwif_conf_clui_opt_set,
	                &nwif_conf_clui_cmd,
	                argc,
	                argv);
	if (err)
		return EXIT_FAILURE;

	memset(&ctx, 0, sizeof(ctx));
	ctx.path = NWIF_CONF_DIR_PATH;

	err = clui_parse(&parser, argc, argv, &ctx);
	if (err)
		return EXIT_FAILURE;

	err = ctx.exec(&ctx, &parser);

	return !err ? EXIT_SUCCESS : EXIT_FAILURE;
}
