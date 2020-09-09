#include "nwif/config.h"
#include "ui.h"
#include <nwif/conf.h>
#include <utils/net.h>
#include <utils/path.h>
#include <clui/clui.h>
#include <libsmartcols/libsmartcols.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define NWIF_CONF_DIR_PATH CONFIG_NWIF_LOCALSTATEDIR

#if defined(CONFIG_NWIF_ASSERT)

#include <utils/assert.h>

#define nwif_conf_clui_assert(_expr) \
	uassert("nwif_conf", _expr)

#else  /* !defined(CONFIG_NWIF_ASSERT) */

#define nwif_conf_clui_assert(_expr)

#endif /* defined(CONFIG_NWIF_ASSERT) */

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

struct nwif_conf_clui_ctx {
	nwif_conf_clui_exec_fn         *exec;
	const char                     *path;
	union {
		const struct clui_cmd  *cmd;
		const char             *iface_name;
		struct nwif_iface_conf *iface_conf;
	};
};

static void
nwif_conf_clui_sched_exec(void *ctx, nwif_conf_clui_exec_fn *exec)
{
	nwif_conf_clui_assert(ctx);
	nwif_conf_clui_assert(exec);
	nwif_conf_clui_assert(!((struct nwif_conf_clui_ctx *)ctx)->exec);

	((struct nwif_conf_clui_ctx *)ctx)->exec = exec;
}

static int
nwif_conf_clui_exec_help(const struct nwif_conf_clui_ctx *ctx,
                         const struct clui_parser        *parser)
{
	nwif_conf_clui_assert(ctx);

	clui_help_cmd(ctx->cmd, parser, stdout);

	return 0;
}

static void
nwif_conf_clui_sched_help(void *ctx, const struct clui_cmd *cmd)
{
	nwif_conf_clui_assert(ctx);

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

#define nwif_conf_clui_assert_session(_sess) \
	nwif_conf_clui_assert(_sess); \
	nwif_conf_clui_assert((_sess)->repo); \
	nwif_conf_clui_assert((_sess)->parser)

static int
nwif_conf_begin_clui_session(struct nwif_conf_clui_session *session,
                             const char                    *path,
                             const struct clui_parser      *parser)
{
	nwif_conf_clui_assert(session);
	nwif_conf_clui_assert(upath_validate_path_name(path) > 0);
	nwif_conf_clui_assert(parser);
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
	nwif_conf_clui_assert_session(session);

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
	nwif_conf_clui_assert(cmd);
	nwif_conf_clui_assert(parser);
	nwif_conf_clui_assert(arg);
	nwif_conf_clui_assert(ctx);

	ssize_t                 len;
	struct nwif_iface_conf *conf = ((struct nwif_conf_clui_ctx *)
	                                ctx)->iface_conf;

	nwif_conf_clui_assert(conf);

	len = nwif_ui_parse_iface_name(arg);
	if (len < 0) {
		nwif_conf_clui_err(parser,
		                   len,
		                   "invalid interface name '%.*s' requested",
		                   IFNAMSIZ,
		                   arg);
		return len;
	}

	nwif_iface_conf_set_name(conf, arg, len);

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
	nwif_conf_clui_assert(cmd);
	nwif_conf_clui_assert(parser);
	nwif_conf_clui_assert(arg);
	nwif_conf_clui_assert(ctx);

	int                     err;
	uint8_t                 oper;
	const char             *reason;
	struct nwif_iface_conf *conf = ((struct nwif_conf_clui_ctx *)
	                                ctx)->iface_conf;

	nwif_conf_clui_assert(conf);

	err = nwif_ui_parse_oper_state(arg, &oper);
	switch (err) {
	case 0:
		nwif_iface_conf_set_oper_state(conf, oper);
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
	nwif_conf_clui_assert(cmd);
	nwif_conf_clui_assert(parser);
	nwif_conf_clui_assert(arg);
	nwif_conf_clui_assert(ctx);

	int                     err;
	uint32_t                mtu;
	struct nwif_iface_conf *conf = ((struct nwif_conf_clui_ctx *)
	                                ctx)->iface_conf;

	nwif_conf_clui_assert(conf);

	err = nwif_ui_parse_mtu(arg, &mtu);
	if (!err) {
		nwif_iface_conf_set_mtu(conf, mtu);
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
nwif_conf_clui_new_iface(struct nwif_conf_clui_session *session,
                         struct nwif_iface_conf        *conf)
{
	nwif_conf_clui_assert_session(session);

	session->err = nwif_iface_conf_save(conf,
	                                    &session->xact,
	                                    session->repo);

	return session->err;
}

static int
nwif_conf_clui_exec_new_iface(const struct nwif_conf_clui_ctx *ctx,
                              const struct clui_parser        *parser)
{
	nwif_conf_clui_assert(ctx);

	struct nwif_conf_clui_session sess;
	int                           ret;

	ret = nwif_conf_begin_clui_session(&sess, ctx->path, parser);
	if (ret)
		goto destroy;

	nwif_conf_clui_new_iface(&sess, ctx->iface_conf);

	ret = nwif_conf_close_clui_session(&sess);

destroy:
	nwif_iface_conf_destroy(ctx->iface_conf);

	return ret;
}

/******************************************************************************
 * Ethernet interface handling
 ******************************************************************************/

#if defined(CONFIG_NWIF_ETHER)

#include <nwif/ether.h>
#include <netinet/ether.h>

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

static ssize_t
nwif_conf_clui_parse_ether_syspath(const struct clui_parser *parser,
                                   const char               *arg,
                                   struct nwif_iface_conf   *conf)
{
	nwif_conf_clui_assert(parser);
	nwif_conf_clui_assert(arg);
	nwif_conf_clui_assert(conf);

	char       *syspath;
	ssize_t     ret;
	const char *reason;

	ret = nwif_ui_normalize_syspath(arg, &syspath);
	if (ret > 0) {
		nwif_ether_conf_set_syspath(nwif_ether_conf_from_iface(conf),
		                            syspath,
		                            (size_t)ret);
		free(syspath);
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

static int
nwif_conf_clui_parse_ether_hwaddr(const struct clui_cmd *cmd,
                                  struct clui_parser    *parser,
                                  const char            *arg,
                                  void                  *ctx)
{
	nwif_conf_clui_assert(cmd);
	nwif_conf_clui_assert(parser);
	nwif_conf_clui_assert(arg);
	nwif_conf_clui_assert(ctx);

	int                     err;
	struct ether_addr       addr;
	const char             *reason;
	struct nwif_iface_conf *conf = ((struct nwif_conf_clui_ctx *)
	                                ctx)->iface_conf;

	nwif_conf_clui_assert(conf);

	err = nwif_ui_parse_hwaddr(arg, &addr);
	switch (err) {
	case 0:
		nwif_ether_conf_set_hwaddr(nwif_ether_conf_from_iface(conf),
		                           &addr);
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

static const struct clui_kword_parm nwif_conf_clui_ether_hwaddr_parm = {
	.kword = "hwaddr",
	.parse = nwif_conf_clui_parse_ether_hwaddr
};

static const struct clui_kword_parm * const nwif_ether_conf_option_parms[] = {
	&nwif_conf_clui_iface_name_parm,
	&nwif_conf_clui_iface_oper_state_parm,
	&nwif_conf_clui_iface_mtu_parm,
	&nwif_conf_clui_ether_hwaddr_parm
};

static int
nwif_conf_clui_parse_new_ether(const struct clui_cmd *cmd,
                               struct clui_parser    *parser,
                               int                    argc,
                               char * const           argv[],
                               void                  *ctx)
{
	nwif_conf_clui_assert(ctx);

	struct nwif_ether_conf    *conf;
	struct nwif_conf_clui_ctx *nctx;
	int                        ret;

	if (argc < 1 || argc > 9) {
		clui_err(parser, "invalid number of arguments.\n");
		goto help;
	}

	if (!strcmp(argv[0], "help")) {
		nwif_conf_clui_sched_help(ctx, cmd);
		return 0;
	}

	conf = nwif_ether_conf_create();
	if (!conf) {
		ret = -errno;
		nwif_conf_clui_err(
			parser,
			ret,
			"failed to allocate interface");
		return ret;
	}

	nctx = (struct nwif_conf_clui_ctx *)ctx;
	nctx->iface_conf = nwif_ether_conf_to_iface(conf);

	ret = nwif_conf_clui_parse_ether_syspath(parser,
	                                         argv[0],
	                                         nctx->iface_conf);
	if (ret)
		goto destroy;

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
			goto destroy;
	}

	nwif_conf_clui_sched_exec(ctx, nwif_conf_clui_exec_new_iface);

	return 0;

destroy:
	nwif_iface_conf_destroy(nctx->iface_conf);

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

static int
nwif_conf_clui_render_ether(struct libscols_line         *line,
                            const struct nwif_iface_conf *iface)
{
	const struct nwif_ether_conf *conf = nwif_ether_conf_from_iface(iface);
	int                           err;
	const struct ether_addr      *hwaddr;

	/* Render sysfs device path. */
	err = scols_line_set_data(line,
	                          NWIF_CONF_CLUI_IFACE_SYSPATH_CID,
	                          nwif_ether_conf_get_syspath(conf));
	if (err)
		return err;

	/* Render optional hardware address. */
	hwaddr = nwif_ether_conf_get_hwaddr(conf);
	if (hwaddr) {
		char *str;

		str = malloc(UNET_HWADDR_STRING_MAX);
		if (!str)
			return -errno;

		ether_ntoa_r(hwaddr, str);
		err = scols_line_refer_data(line,
		                            NWIF_CONF_CLUI_IFACE_HWADDR_CID,
		                            str);
		nwif_conf_clui_assert(!err);
	}

	return 0;
}

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
	nwif_conf_clui_assert(ctx);

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
 * iface show command handling
 ******************************************************************************/

#define NWIF_CONF_CLUI_IFACE_SHOW_HELP \
	"Synopsis:\n" \
	"    %1$s iface show <IFACE_NAME>\n" \
	"    Show properties of interface specified by <IFACE_NAME>.\n" \
	"\n" \
	"    %1$s iface show [all]\n" \
	"    Show properties of all interfaces.\n" \
	"\n" \
	"    %1$s iface show help\n" \
	"    This help message.\n" \
	"\n" \
	"Where:\n" \
	"    <IFACE_NAME> -- interface name.\n"

struct nwif_conf_clui_iface_col_desc {
	const char *label;
	double      whint;
	int         flags;
};

static const struct nwif_conf_clui_iface_col_desc 
nwif_conf_clui_iface_cols[NWIF_CONF_CLUI_IFACE_CID_NR] = {
	[NWIF_CONF_CLUI_IFACE_ID_CID] = {
		.label = "ID",
		.whint = 1.0,
		.flags = SCOLS_FL_RIGHT
	},
	[NWIF_CONF_CLUI_IFACE_TYPE_CID] = {
		.label = "TYPE",
		.whint = 1.0,
		.flags = 0
	},
	[NWIF_CONF_CLUI_IFACE_NAME_CID] = {
		.label = "NAME",
		.whint = 1.0,
		.flags = 0
	},
	[NWIF_CONF_CLUI_IFACE_OPER_STATE_CID] = {
		.label = "OPER",
		.whint = 1.0,
		.flags = 0
	},
	[NWIF_CONF_CLUI_IFACE_MTU_CID] = {
		.label = "MTU",
		.whint = 1.0,
		.flags = 0
	},
	[NWIF_CONF_CLUI_IFACE_SYSPATH_CID] = {
		.label = "SYSPATH",
		.whint = 1.0,
		.flags = SCOLS_FL_WRAP
	},
	[NWIF_CONF_CLUI_IFACE_HWADDR_CID] = {
		.label = "HWADDR",
		.whint = 1.0,
		.flags = 0
	}
};

static struct libscols_table *
nwif_conf_clui_new_iface_table(void)
{
	struct libscols_table *tbl;
	unsigned int           c;

	tbl = scols_new_table();
	if (!tbl)
		return NULL;

	scols_table_enable_header_repeat(tbl, 1);

	for (c = 0; c < array_nr(nwif_conf_clui_iface_cols); c++) {
		const struct nwif_conf_clui_iface_col_desc *col;

		col = &nwif_conf_clui_iface_cols[c];
		if (!scols_table_new_column(tbl,
		                            col->label,
		                            col->whint,
		                            col->flags))
			goto unref;
	}

	return tbl;

unref:
	scols_unref_table(tbl);

	return NULL;
}

static int
nwif_conf_clui_render_iface(struct libscols_table        *table,
                            const struct nwif_iface_conf *iface)
{
	struct libscols_line         *line;
	struct kvs_autoidx_id         id;
	char                         *str;
	int                           err;
	enum nwif_iface_type          type;
	const char                   *name;
	uint8_t                       oper;
	uint32_t                      mtu;

	line = scols_table_new_line(table, NULL);
	if (!line)
		return -errno;

	/*
	 * Render interface config id.
	 * TODO: find a way to print id in a portable manner ?!
	 */
	id = nwif_iface_conf_get_id(iface);
	if (asprintf(&str,
	             "%" PRIx32 ".%04" PRIx16,
	             id.rid.pgno,
	             id.rid.indx) < 0)
		return -errno;
	err = scols_line_refer_data(line, NWIF_CONF_CLUI_IFACE_ID_CID, str);
	nwif_conf_clui_assert(!err);

	/* Render interface type. */
	type = nwif_iface_conf_get_type(iface);
	err = scols_line_set_data(line,
	                          NWIF_CONF_CLUI_IFACE_TYPE_CID,
	                          nwif_ui_get_iface_type_label(type));
	if (err)
		return err;

	/* Render optional interface name */
	name = nwif_iface_conf_get_name(iface);
	if (name) {
		err = scols_line_set_data(line,
		                          NWIF_CONF_CLUI_IFACE_NAME_CID,
		                          name);
		if (err)
			return err;
	}

	/* Render optional operational state. */
	nwif_iface_conf_get_oper_state(iface, &oper);
	err = scols_line_set_data(line,
	                          NWIF_CONF_CLUI_IFACE_OPER_STATE_CID,
	                          nwif_ui_get_oper_state_label(oper));
	if (err)
		return err;

	/* Render optional MTU. */
	err = nwif_iface_conf_get_mtu(iface, &mtu);
	if (!err) {
		if (asprintf(&str, "%" PRIu16, mtu) < 0)
			return -errno;
		err = scols_line_refer_data(line,
		                            NWIF_CONF_CLUI_IFACE_MTU_CID,
		                            str);
		nwif_conf_clui_assert(!err);
	}

	/* Now render interface type specific infos. */
	switch (type) {
#if defined(CONFIG_NWIF_ETHER)
	case NWIF_ETHER_IFACE_TYPE:
		return nwif_conf_clui_render_ether(line, iface);
#endif /* defined(CONFIG_NWIF_ETHER) */

	default:
		nwif_conf_clui_assert(0);
	}
}

static int
nwif_conf_clui_show_all_ifaces(struct nwif_conf_clui_session *session)
{
	nwif_conf_clui_assert_session(session);

	struct libscols_table   *tbl;
	struct kvs_iter          iter;
        struct kvs_autoidx_desc  desc;
	int                      err;

	err = nwif_iface_conf_init_iter(session->repo, &session->xact, &iter);
	if (err) {
		nwif_conf_clui_err(
			session->parser,
			err,
			"failed to start browsing interfaces configuration");
		goto err;
	}

	tbl = nwif_conf_clui_new_iface_table();
	if (!tbl) {
		nwif_conf_clui_err(
			session->parser,
			err,
			"failed to allocate interfaces configuration table");
		goto fini;
	}

	for (err = nwif_iface_conf_iter_first(&iter, &desc);
	     !err;
	     err = nwif_iface_conf_iter_next(&iter, &desc)) {
		struct nwif_iface_conf *iface;

		iface = nwif_iface_conf_create_from_desc(&desc);
		if (!iface) {
			err = -errno;
			break;
		}

		err = nwif_conf_clui_render_iface(tbl, iface);

		nwif_iface_conf_destroy(iface);
	}

	if (err && (err != -ENOENT)) {
		nwif_conf_clui_err(
			session->parser,
			err,
			"failed to browse interfaces configuration");
		goto unref;
	}

	scols_print_table(tbl);

	scols_unref_table(tbl);

	err = nwif_iface_conf_fini_iter(&iter);
	if (err) {
		nwif_conf_clui_err(
			session->parser,
			err,
			"failed to stop browsing interfaces configuration");
		goto err;
	}

	return 0;

unref:
	scols_unref_table(tbl);

fini:
	nwif_iface_conf_fini_iter(&iter);

err:
	session->err = err;

	return err;
}

static int
nwif_conf_clui_show_one_iface(struct nwif_conf_clui_session *session,
                              const char                    *name)
{
#warning IMPLEMENT ME!!

	return -ENOSYS;
}

static int
nwif_conf_clui_exec_show_all_ifaces(const struct nwif_conf_clui_ctx *ctx,
                                    const struct clui_parser        *parser)
{
	nwif_conf_clui_assert(ctx);

	struct nwif_conf_clui_session sess;
	int                           err;

	err = nwif_conf_begin_clui_session(&sess, ctx->path, parser);
	if (err)
		return err;

	nwif_conf_clui_show_all_ifaces(&sess);

	return nwif_conf_close_clui_session(&sess);
}

static int
nwif_conf_clui_exec_show_one_iface(const struct nwif_conf_clui_ctx *ctx,
                                   const struct clui_parser        *parser)
{
	nwif_conf_clui_assert(ctx);

	struct nwif_conf_clui_session sess;
	int                           err;

	err = nwif_conf_begin_clui_session(&sess, ctx->path, parser);
	if (err)
		return err;

	nwif_conf_clui_show_one_iface(&sess, ctx->iface_name);

	return nwif_conf_close_clui_session(&sess);
}

static int
nwif_conf_clui_parse_iface_show(const struct clui_cmd *cmd,
                                struct clui_parser    *parser,
                                int                    argc,
                                char * const           argv[],
                                void                  *ctx)
{
	nwif_conf_clui_assert(ctx);

	if (argc == 1) {
		const char *arg = argv[0];

		if (!strcmp(arg, "help")) {
			nwif_conf_clui_sched_help(ctx, cmd);
			return 0;
		}

		if (!strcmp(arg, "all")) {
			nwif_conf_clui_sched_exec(
				ctx, nwif_conf_clui_exec_show_all_ifaces);
			return 0;
		}

		if (unet_check_iface_name(arg) < 0) {
			clui_err(parser, "invalid interface name '%s'.", arg);
			return -EINVAL;
		}

		((struct nwif_conf_clui_ctx *)ctx)->iface_name = arg;
		nwif_conf_clui_sched_exec(ctx,
		                          nwif_conf_clui_exec_show_one_iface);
		return 0;
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
 * iface command handling
 ******************************************************************************/

#define NWIF_CONF_CLUI_IFACE_HELP \
	"Synopsis:\n" \
	"    %1$s iface show [IFACE_SHOW_SPEC] | help\n" \
	"    Show properties of interface according to [IFACE_SHOW_SPEC].\n" \
	"\n" \
	"    %1$s iface new <IFACE_NEW_SPEC> | help\n" \
	"    Create new interface according to <IFACE_NEW_SPEC>.\n" \
	"\n" \
	"    %1$s iface help\n" \
	"    This help message.\n" \
	"\n" \
	"Where:\n" \
	"    [IFACE_SHOW_SPEC] -- optional show interface specification.\n" \
	"    <IFACE_NEW_SPEC>  -- mandatory new interface specification.\n"

static int
nwif_conf_clui_parse_iface(const struct clui_cmd *cmd,
                           struct clui_parser    *parser,
                           int                    argc,
                           char * const           argv[],
                           void                  *ctx)
{
	nwif_conf_clui_assert(ctx);

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
#if 0
	else if (!strcmp(argv[0], "set")) {
		return clui_parse_cmd(&nwif_conf_clui_iface_set_cmd,
		                      parser,
		                      argc - 1,
		                      &argv[1],
		                      ctx);
	}
	else if (!strcmp(argv[0], "clear")) {
		return clui_parse_cmd(&nwif_conf_clui_iface_clear_cmd,
		                      parser,
		                      argc - 1,
		                      &argv[1],
		                      ctx);
	}
	else if (!strcmp(argv[0], "del")) {
		return clui_parse_cmd(&nwif_conf_clui_iface_del_cmd,
		                      parser,
		                      argc - 1,
		                      &argv[1],
		                      ctx);
	}
#endif
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
	nwif_conf_clui_assert(ctx);

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
	nwif_conf_clui_assert(opt);
	nwif_conf_clui_assert(parser);
	nwif_conf_clui_assert(arg);
	nwif_conf_clui_assert(ctx);

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
