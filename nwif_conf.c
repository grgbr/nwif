#include "common.h"
#include "ui.h"
#include "conf_priv.h"
#include "iface_priv.h"
#include <utils/path.h>
#include <utils/signal.h>
#include <clui/clui.h>
#include <clui/shell.h>
#include <string.h>
#include <locale.h>
#include <sys/stat.h>

#define NWIF_CLUI_CONF_PROMPT "nwif_conf> "

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
	uint8_t            admin_state;
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

static bool nwif_conf_clui_shell_mode = false;

/* TODO: clean me up ?? get path field out of context structure ? */
static void
nwif_conf_clui_reset_ctx(struct nwif_conf_clui_ctx *ctx)
{
	const char *path = ctx->path;

	memset(ctx, 0, sizeof(*ctx));
	ctx->path = path;
}

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
	struct kvs_repo          *repo;
	const struct clui_parser *parser;
};

#define nwif_ui_assert_session(_sess) \
	nwif_ui_assert(_sess); \
	nwif_ui_assert((_sess)->repo); \
	nwif_ui_assert((_sess)->parser)

static int
nwif_conf_clui_begin_session(struct nwif_conf_clui_session *session)
{
	nwif_ui_assert_session(session);

	session->err = nwif_conf_begin_xact(session->repo,
	                                    NULL,
	                                    &session->xact,
	                                    0);
	if (session->err)
		nwif_conf_clui_err(session->parser,
		                   session->err,
		                   "failed to begin configuration transaction");

	return session->err;
}

static int
nwif_conf_clui_end_session(struct nwif_conf_clui_session *session)
{
	nwif_ui_assert_session(session);

	int err = session->err;

	session->err = kvs_end_xact(&session->xact, err);

#warning Yack !! Rework me !!
	if (!err && session->err)
		nwif_conf_clui_err(session->parser,
		                   session->err,
		                   "failed to end configuration transaction");

	return session->err;
}

static int
nwif_conf_clui_open_session(struct nwif_conf_clui_session *session,
                            const char                    *path,
                            const struct clui_parser      *parser)
{
	nwif_ui_assert(session);
	nwif_ui_assert(upath_validate_path_name(path) > 0);
	nwif_ui_assert(parser);

	int err;

	session->repo = nwif_conf_create();
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

	session->parser = parser;

	return 0;

free:
	nwif_conf_destroy(session->repo);

	return err;
}

static int
nwif_conf_clui_close_session(const struct nwif_conf_clui_session *session)
{
	nwif_ui_assert_session(session);

	int err = session->err;

	if (err == -ENOTRECOVERABLE)
		goto free;

	if (err) {
		if (nwif_conf_close(session->repo) == -ENOTRECOVERABLE)
			err = -ENOTRECOVERABLE;
	}
	else
		err = nwif_conf_close(session->repo);

#warning Yack !! Rework me !!
	if (!session->err && err)
		nwif_conf_clui_err(session->parser,
		                   err,
		                   "failed to close configuration repository");

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
	NWIF_CONF_CLUI_IFACE_ADMIN_STATE_CID,
	NWIF_CONF_CLUI_IFACE_MTU_CID,
	NWIF_CONF_CLUI_IFACE_SYSPATH_CID,
	NWIF_CONF_CLUI_IFACE_HWADDR_CID,
	NWIF_CONF_CLUI_IFACE_CID_NR
};

static int
nwif_conf_clui_parse_iface_name_parm(const struct clui_cmd *cmd,
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

static const struct clui_kword_parm nwif_conf_clui_iface_name_kword_parm = {
	.label = "name",
	.parse = nwif_conf_clui_parse_iface_name_parm
};

static int
nwif_conf_clui_parse_iface_admin_state_parm(const struct clui_cmd *cmd,
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

	err = nwif_ui_parse_admin_state(arg, &attrs->admin_state);
	switch (err) {
	case 0:
		attrs->mask |= NWIF_ADMIN_STATE_ATTR;
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

static const struct clui_kword_parm
nwif_conf_clui_iface_admin_state_kword_parm = {
	.label = "state",
	.parse = nwif_conf_clui_parse_iface_admin_state_parm
};

static int
nwif_conf_clui_parse_iface_mtu_parm(const struct clui_cmd *cmd,
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
	         "[0:" USTRINGIFY(ETH_MAX_MTU) "] integer expected.",
	         arg);

	return err;
}

static const struct clui_kword_parm nwif_conf_clui_iface_mtu_kword_parm = {
	.label = "mtu",
	.parse = nwif_conf_clui_parse_iface_mtu_parm
};

static int
nwif_conf_clui_parse_iface_syspath_parm(const struct clui_cmd *cmd,
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

static const struct clui_kword_parm nwif_conf_clui_iface_syspath_kword_parm = {
	.label = "syspath",
	.parse = nwif_conf_clui_parse_iface_syspath_parm
};

static int
nwif_conf_clui_parse_iface_hwaddr_parm(const struct clui_cmd *cmd,
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

static const struct clui_kword_parm nwif_conf_clui_iface_hwaddr_kword_parm = {
	.label = "hwaddr",
	.parse = nwif_conf_clui_parse_iface_hwaddr_parm
};

static int
nwif_conf_clui_parse_iface_name_switch(const struct clui_cmd *cmd,
                                       struct clui_parser    *parser,
                                       void                  *ctx)
{
	nwif_ui_assert(cmd);
	nwif_ui_assert(parser);
	nwif_ui_assert(ctx);

	struct nwif_iface_conf_attrs *attrs = &((struct nwif_conf_clui_ctx *)
	                                        ctx)->iface_attrs;

	attrs->mask |= NWIF_NAME_ATTR;

	return 0;
}

static const struct clui_switch_parm nwif_conf_clui_iface_name_switch_parm = {
	.label = "name",
	.parse = nwif_conf_clui_parse_iface_name_switch
};

static int
nwif_conf_clui_parse_iface_admin_state_switch(const struct clui_cmd *cmd,
                                              struct clui_parser    *parser,
                                              void                  *ctx)
{
	nwif_ui_assert(cmd);
	nwif_ui_assert(parser);
	nwif_ui_assert(ctx);

	struct nwif_iface_conf_attrs *attrs = &((struct nwif_conf_clui_ctx *)
	                                        ctx)->iface_attrs;

	attrs->mask |= NWIF_ADMIN_STATE_ATTR;

	return 0;
}

static const struct clui_switch_parm
nwif_conf_clui_iface_admin_state_switch_parm = {
	.label = "state",
	.parse = nwif_conf_clui_parse_iface_admin_state_switch
};

static int
nwif_conf_clui_parse_iface_mtu_switch(const struct clui_cmd *cmd,
                                      struct clui_parser    *parser,
                                      void                  *ctx)
{
	nwif_ui_assert(cmd);
	nwif_ui_assert(parser);
	nwif_ui_assert(ctx);

	struct nwif_iface_conf_attrs *attrs = &((struct nwif_conf_clui_ctx *)
	                                        ctx)->iface_attrs;

	attrs->mask |= NWIF_MTU_ATTR;

	return 0;
}

static const struct clui_switch_parm nwif_conf_clui_iface_mtu_switch_parm = {
	.label = "mtu",
	.parse = nwif_conf_clui_parse_iface_mtu_switch
};

static int
nwif_conf_clui_parse_iface_hwaddr_switch(const struct clui_cmd *cmd,
                                         struct clui_parser    *parser,
                                         void                  *ctx)
{
	nwif_ui_assert(cmd);
	nwif_ui_assert(parser);
	nwif_ui_assert(ctx);

	struct nwif_iface_conf_attrs *attrs = &((struct nwif_conf_clui_ctx *)
	                                        ctx)->iface_attrs;

	attrs->mask |= NWIF_HWADDR_ATTR;

	return 0;
}

static const struct clui_switch_parm nwif_conf_clui_iface_hwaddr_switch_parm = {
	.label = "hwaddr",
	.parse = nwif_conf_clui_parse_iface_hwaddr_switch
};

/******************************************************************************
 * Ethernet interface handling
 ******************************************************************************/

#if defined(CONFIG_NWIF_ETHER)

#include "ether_priv.h"

#define NWIF_CONF_CLUI_IFACE_NEW_ETHER_SYNOPSIS \
	"    %1$s%2$siface new ether <ETHER_NEW_SPEC> | help\n" \
	"    Create a new ethernet interface.\n" \
	"\n"

#define NWIF_CONF_CLUI_IFACE_NEW_ETHER_WHERE \
	"    <ETHER_NEW_SPEC> -- mandatory new ethernet interface specification.\n"

#define NWIF_CONF_CLUI_IFACE_SET_ETHER_SYNOPSIS \
	"    %1$s%2$siface set <IFACE_ID> <ETHER_SET_SPEC>\n" \
	"    %1$s%2$siface set <IFACE_NAME> <ETHER_SET_SPEC>\n" \
	"    Setup attributes of ethernet interface specified by <IFACE_ID> or\n" \
	"    <IFACE_NAME> according to <ETHER_SET_SPEC>.\n" \
	"\n" \

#define NWIF_CONF_CLUI_IFACE_SET_ETHER_WITH \
	"    ETHER_SET_SPEC := [SYSPATH_SPEC] [NAME_SPEC] [STATE_SPEC] [MTU_SPEC] [HWADDR_SPEC]\n"

#define NWIF_CONF_CLUI_IFACE_CLEAR_ETHER_SYNOPSIS \
	"    %1$s%2$siface clear <IFACE_ID> <ETHER_CLEAR_SPEC>\n" \
	"    %1$s%2$siface clear <IFACE_NAME> <ETHER_CLEAR_SPEC>\n" \
	"    Clear attribute(s) of ethernet interface specified by <IFACE_ID> or\n" \
	"    <IFACE_NAME> according to <ETHER_CLEAR_SPEC>.\n" \
	"\n" \

#define NWIF_CONF_CLUI_IFACE_CLEAR_ETHER_WITH \
	"    ETHER_CLEAR_SPEC := [name] [oper] [mtu] [hwaddr]\n"

#define NWIF_CONF_CLUI_NEW_ETHER_HELP \
	"Synopsis:\n" \
	"    %1$s%2$siface new ether <SYSPATH> [NAME_SPEC] [STATE_SPEC] [MTU_SPEC] [HWADDR_SPEC]\n" \
	"    Create a new ethernet interface.\n" \
	"\n" \
	"    %1$s%2$siface new ether help\n" \
	"    This help message.\n" \
	"\n" \
	"With:\n" \
	"    NAME_SPEC   := name <IFACE_NAME>\n" \
	"    STATE_SPEC  := state <IFACE_STATE>\n" \
	"    IFACE_STATE := up|down\n" \
	"    MTU_SPEC    := mtu <IFACE_MTU>\n" \
	"    HWADDR_SPEC := hwaddr <IFACE_HWADDR>\n" \
	"\n" \
	"Where:\n" \
	"    <SYSPATH>      -- sysfs network interface path, a non empty string.\n" \
	"    <IFACE_NAME>   -- interface name, a non empty string.\n" \
	"    <IFACE_STATE>  -- interface administrative state.\n" \
	"    <IFACE_MTU>    -- maximum transfer unit in bytes,\n" \
	"                      integer [0:" USTRINGIFY(ETH_MAX_MTU) "].\n" \
	"    <IFACE_HWADDR> -- unicast 48-bit MAC address, standard hexadecimal\n" \
	"                      digits and colons notation.\n"

static const struct clui_kword_parm * const nwif_ether_conf_kword_parms[] = {
	&nwif_conf_clui_iface_name_kword_parm,
	&nwif_conf_clui_iface_admin_state_kword_parm,
	&nwif_conf_clui_iface_mtu_kword_parm,
	&nwif_conf_clui_iface_hwaddr_kword_parm
};

static int
nwif_conf_clui_fill_ether(struct nwif_ether_conf             *conf,
                          const struct nwif_iface_conf_attrs *attrs)
{
	nwif_ui_assert(conf);
	nwif_ui_assert(attrs);

	struct nwif_iface_conf *iface = nwif_ether_conf_to_iface(conf);

	if (attrs->mask & ~(NWIF_NAME_ATTR | NWIF_ADMIN_STATE_ATTR |
	                    NWIF_MTU_ATTR | NWIF_SYSPATH_ATTR |
	                    NWIF_HWADDR_ATTR))
		return -ENOTSUP;

	if (attrs->mask & NWIF_NAME_ATTR)
		nwif_iface_conf_set_name(iface,
		                         attrs->name,
		                         strlen(attrs->name));

	if (attrs->mask & NWIF_ADMIN_STATE_ATTR)
		nwif_iface_conf_set_admin_state(iface, attrs->admin_state);

	if (attrs->mask & NWIF_MTU_ATTR)
		nwif_iface_conf_set_mtu(iface, attrs->mtu);

	if (attrs->mask & NWIF_SYSPATH_ATTR)
		nwif_ether_conf_set_syspath(conf,
		                            attrs->syspath,
		                            strlen(attrs->syspath));

	if (attrs->mask & NWIF_HWADDR_ATTR)
		nwif_ether_conf_set_hwaddr(conf, &attrs->hwaddr);

	return 0;
}

static int
nwif_conf_clui_clear_ether(struct nwif_ether_conf             *conf,
                           const struct nwif_iface_conf_attrs *attrs)
{
	nwif_ui_assert(conf);
	nwif_ui_assert(attrs);

	struct nwif_iface_conf *iface = nwif_ether_conf_to_iface(conf);

	if (attrs->mask & ~(NWIF_NAME_ATTR | NWIF_ADMIN_STATE_ATTR |
	                    NWIF_MTU_ATTR | NWIF_HWADDR_ATTR))
		return -ENOTSUP;

	if (attrs->mask & NWIF_NAME_ATTR)
		nwif_iface_conf_clear_name(iface);

	if (attrs->mask & NWIF_ADMIN_STATE_ATTR)
		nwif_iface_conf_clear_admin_state(iface);

	if (attrs->mask & NWIF_MTU_ATTR)
		nwif_iface_conf_clear_mtu(iface);

	if (attrs->mask & NWIF_HWADDR_ATTR)
		nwif_ether_conf_clear_hwaddr(conf);

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

	ret = nwif_conf_clui_open_session(&sess, ctx->path, parser);
	if (ret)
		goto free;

	conf = nwif_ether_conf_create(nwif_conf_get_iface_table(sess.repo));
	if (!conf) {
		sess.err = -errno;
		nwif_conf_clui_err(parser,
		                   sess.err,
		                   "failed to allocate interface");
		goto close;
	}

	sess.err = nwif_conf_clui_fill_ether(conf, &ctx->iface_attrs);
	if (sess.err) {
		clui_err(parser,
		         "failed to create ethernet interface: "
		         "unexpected attribute(s).");
		goto destroy;
	}

	if (nwif_conf_clui_begin_session(&sess))
		goto destroy;

	sess.err = nwif_iface_conf_save(nwif_ether_conf_to_iface(conf),
	                                &sess.xact);
	if (sess.err)
		nwif_conf_clui_err(parser,
		                   sess.err,
		                   "failed to create ethernet interface");

	nwif_conf_clui_end_session(&sess);

destroy:
	nwif_iface_conf_destroy(nwif_ether_conf_to_iface(conf));

close:
	ret = nwif_conf_clui_close_session(&sess);

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

	ret = nwif_conf_clui_parse_iface_syspath_parm(cmd,
	                                              parser,
	                                              argv[0],
	                                              ctx);
	if (ret)
		return ret;

	if (argc > 1) {
		ret = clui_parse_all_kword_parms(
			cmd,
			parser,
			nwif_ether_conf_kword_parms,
			array_nr(nwif_ether_conf_kword_parms),
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
	if (nwif_conf_clui_shell_mode)
		fprintf(stdio, NWIF_CONF_CLUI_NEW_ETHER_HELP, "", "");
	else
		fprintf(stdio,
		        NWIF_CONF_CLUI_NEW_ETHER_HELP,
		        parser->argv0,
		        " ");
}

static const struct clui_cmd nwif_conf_clui_new_ether_cmd = {
	.parse = nwif_conf_clui_parse_new_ether,
	.help  = nwif_conf_clui_new_ether_help
};

#else /* !defined(CONFIG_NWIF_ETHER) */

#define NWIF_CONF_CLUI_IFACE_NEW_ETHER_SYNOPSIS
#define NWIF_CONF_CLUI_IFACE_NEW_ETHER_WHERE
#define NWIF_CONF_CLUI_IFACE_SET_ETHER_SYNOPSIS
#define NWIF_CONF_CLUI_IFACE_SET_ETHER_WITH

#endif /* defined(CONFIG_NWIF_ETHER) */

/******************************************************************************
 * iface new command handling
 ******************************************************************************/

#define NWIF_CONF_CLUI_IFACE_NEW_HELP \
	"Synopsis:\n" \
	NWIF_CONF_CLUI_IFACE_NEW_ETHER_SYNOPSIS \
	"    %1$s%2$siface new help\n" \
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
	if (nwif_conf_clui_shell_mode)
		fprintf(stdio, NWIF_CONF_CLUI_IFACE_NEW_HELP, "", "");
	else
		fprintf(stdio,
		        NWIF_CONF_CLUI_IFACE_NEW_HELP,
		        parser->argv0,
		        " ");
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
	NWIF_CONF_CLUI_IFACE_SET_ETHER_SYNOPSIS \
	"    %1$s%2$siface set help\n" \
	"    This help message.\n" \
	"\n" \
	"With:\n" \
	NWIF_CONF_CLUI_IFACE_SET_ETHER_WITH \
	"    SYSPATH_SPEC   := syspath <SYSPATH>\n" \
	"    NAME_SPEC      := name <IFACE_NAME>\n" \
	"    STATE_SPEC     := state <IFACE_STATE>\n" \
	"    IFACE_STATE    := up|down\n" \
	"    MTU_SPEC       := mtu <IFACE_MTU>\n" \
	"    HWADDR_SPEC    := hwaddr <IFACE_HWADDR>\n" \
	"\n" \
	"Where:\n" \
	NWIF_CONF_CLUI_IFACE_ID_WHERE \
	NWIF_CONF_CLUI_IFACE_NAME_WHERE \
	"    <SYSPATH>      -- sysfs network interface path, a non empty string.\n" \
	"    <IFACE_NAME>   -- interface name, a non empty string.\n" \
	"    <IFACE_STATE>  -- interface administrative state.\n" \
	"    <IFACE_MTU>    -- maximum transfer unit in bytes,\n" \
	"                      integer [0:" USTRINGIFY(ETH_MAX_MTU) "].\n" \
	"    <IFACE_HWADDR> -- unicast 48-bit MAC address, standard hexadecimal\n" \
	"                      digits and colons notation.\n"

static const struct clui_kword_parm * const nwif_iface_conf_kword_parms[] = {
	&nwif_conf_clui_iface_syspath_kword_parm,
	&nwif_conf_clui_iface_name_kword_parm,
	&nwif_conf_clui_iface_admin_state_kword_parm,
	&nwif_conf_clui_iface_mtu_kword_parm,
	&nwif_conf_clui_iface_hwaddr_kword_parm
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

	ret = nwif_conf_clui_open_session(&sess, ctx->path, parser);
	if (ret)
		goto free;

	if (nwif_conf_clui_begin_session(&sess))
		goto close;

	conf = nwif_iface_conf_create_byid(nwif_conf_get_iface_table(sess.repo),
	                                   &sess.xact,
	                                   ctx->iface_id);
	if (!conf) {
		sess.err = -errno;
		nwif_conf_clui_err(parser,
		                   sess.err,
		                   "failed to load '%" PRIx64 "' interface",
		                   ctx->iface_id);
		goto end;
	}

	switch (nwif_iface_conf_get_type(conf)) {
#if defined(CONFIG_NWIF_ETHER)
	case NWIF_ETHER_IFACE_TYPE:
		sess.err = nwif_conf_clui_fill_ether(
			nwif_ether_conf_from_iface(conf), attrs);
		if (sess.err) {
			clui_err(parser,
			         "failed to setup '%" PRIx64 "' ethernet "
			         "interface: unexpected attribute(s).",
		                 ctx->iface_id);
		}
		break;
#endif /* defined(CONFIG_NWIF_ETHER) */

	default:
		nwif_ui_assert(0);
	}

	if (sess.err)
		goto destroy;

	sess.err = nwif_iface_conf_save(conf, &sess.xact);
	if (sess.err)
		nwif_conf_clui_err(parser,
		                   sess.err,
		                   "failed to save '%" PRIx64 "' interface",
		                   ctx->iface_id);

destroy:
	nwif_iface_conf_destroy(conf);

end:
	nwif_conf_clui_end_session(&sess);

close:
	ret = nwif_conf_clui_close_session(&sess);

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

	ret = nwif_conf_clui_open_session(&sess, ctx->path, parser);
	if (ret)
		goto free;

	if (nwif_conf_clui_begin_session(&sess))
		goto close;

	conf = nwif_iface_conf_create_byname(
		nwif_conf_get_iface_table(sess.repo),
		&sess.xact,
		ctx->iface_name,
		strlen(ctx->iface_name));
	if (!conf) {
		sess.err = -errno;
		nwif_conf_clui_err(parser,
		                   sess.err,
		                   "failed to load '%s' interface",
		                   ctx->iface_name);
		goto end;
	}

	switch (nwif_iface_conf_get_type(conf)) {
#if defined(CONFIG_NWIF_ETHER)
	case NWIF_ETHER_IFACE_TYPE:
		sess.err = nwif_conf_clui_fill_ether(
			nwif_ether_conf_from_iface(conf), attrs);
		if (sess.err) {
			clui_err(parser,
			         "failed to setup '%s' ethernet interface: "
			         "unexpected attribute(s).",
			         ctx->iface_name);
		}
		break;
#endif /* defined(CONFIG_NWIF_ETHER) */

	default:
		nwif_ui_assert(0);
	}

	if (sess.err)
		goto destroy;

	sess.err = nwif_iface_conf_save(conf, &sess.xact);
	if (sess.err)
		nwif_conf_clui_err(parser,
		                   sess.err,
		                   "failed to save '%s' interface",
		                   ctx->iface_name);

destroy:
	nwif_iface_conf_destroy(conf);

end:
	nwif_conf_clui_end_session(&sess);

close:
	ret = nwif_conf_clui_close_session(&sess);

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
	ret = clui_parse_all_kword_parms(
		cmd,
		parser,
		nwif_iface_conf_kword_parms,
		array_nr(nwif_iface_conf_kword_parms),
		argc - 1,
		&argv[1],
		ctx);
	if (ret)
		goto free;

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
	if (nwif_conf_clui_shell_mode)
		fprintf(stdio, NWIF_CONF_CLUI_IFACE_SET_HELP, "", "");
	else
		fprintf(stdio,
		        NWIF_CONF_CLUI_IFACE_SET_HELP,
		        parser->argv0,
		        " ");
}

static const struct clui_cmd nwif_conf_clui_iface_set_cmd = {
	.parse = nwif_conf_clui_parse_set_iface,
	.help  = nwif_conf_clui_iface_set_help
};

/******************************************************************************
 * iface clear attribute command handling
 ******************************************************************************/

#define NWIF_CONF_CLUI_IFACE_CLEAR_HELP \
	"Synopsis:\n" \
	NWIF_CONF_CLUI_IFACE_CLEAR_ETHER_SYNOPSIS \
	"    %1$s%2$siface set help\n" \
	"    This help message.\n" \
	"\n" \
	"With:\n" \
	NWIF_CONF_CLUI_IFACE_CLEAR_ETHER_WITH \
	"\n" \
	"Where:\n" \
	NWIF_CONF_CLUI_IFACE_ID_WHERE \
	NWIF_CONF_CLUI_IFACE_NAME_WHERE

static const struct clui_switch_parm * const nwif_iface_conf_switch_parms[] = {
	&nwif_conf_clui_iface_name_switch_parm,
	&nwif_conf_clui_iface_admin_state_switch_parm,
	&nwif_conf_clui_iface_mtu_switch_parm,
	&nwif_conf_clui_iface_hwaddr_switch_parm
};

static int
nwif_conf_clui_exec_clear_iface_byid(const struct nwif_conf_clui_ctx *ctx,
                                     const struct clui_parser        *parser)
{
	nwif_ui_assert(ctx);

	struct nwif_conf_clui_session  sess;
	struct nwif_iface_conf        *conf;
	int                            ret;

	ret = nwif_conf_clui_open_session(&sess, ctx->path, parser);
	if (ret)
		return ret;

	if (nwif_conf_clui_begin_session(&sess))
		goto close;

	conf = nwif_iface_conf_create_byid(nwif_conf_get_iface_table(sess.repo),
	                                   &sess.xact,
	                                   ctx->iface_id);
	if (!conf) {
		sess.err = -errno;
		nwif_conf_clui_err(parser,
		                   sess.err,
		                   "failed to load '%" PRIx64 "' interface",
		                   ctx->iface_id);
		goto end;
	}

	switch (nwif_iface_conf_get_type(conf)) {
#if defined(CONFIG_NWIF_ETHER)
	case NWIF_ETHER_IFACE_TYPE:
		sess.err = nwif_conf_clui_clear_ether(
			nwif_ether_conf_from_iface(conf), &ctx->iface_attrs);
		if (sess.err) {
			clui_err(parser,
			         "failed to clear '%" PRIx64 "' ethernet "
			         "interface attribute(s): "
			         "unexpected attribute(s).",
		                 ctx->iface_id);
		}
		break;
#endif /* defined(CONFIG_NWIF_ETHER) */

	default:
		nwif_ui_assert(0);
	}

	if (sess.err)
		goto destroy;

	sess.err = nwif_iface_conf_save(conf, &sess.xact);
	if (sess.err)
		nwif_conf_clui_err(parser,
		                   sess.err,
		                   "failed to save '%" PRIx64 "' interface",
		                   ctx->iface_id);

destroy:
	nwif_iface_conf_destroy(conf);

end:
	nwif_conf_clui_end_session(&sess);

close:
	return nwif_conf_clui_close_session(&sess);
}

static int
nwif_conf_clui_exec_clear_iface_byname(const struct nwif_conf_clui_ctx *ctx,
                                       const struct clui_parser        *parser)
{
	nwif_ui_assert(ctx);

	struct nwif_conf_clui_session  sess;
	struct nwif_iface_conf        *conf;
	int                            ret;

	ret = nwif_conf_clui_open_session(&sess, ctx->path, parser);
	if (ret)
		return ret;

	if (nwif_conf_clui_begin_session(&sess))
		goto close;

	conf = nwif_iface_conf_create_byname(
		nwif_conf_get_iface_table(sess.repo),
		&sess.xact,
		ctx->iface_name,
		strlen(ctx->iface_name));
	if (!conf) {
		sess.err = -errno;
		nwif_conf_clui_err(parser,
		                   sess.err,
		                   "failed to load '%s' interface",
		                   ctx->iface_name);
		goto end;
	}

	switch (nwif_iface_conf_get_type(conf)) {
#if defined(CONFIG_NWIF_ETHER)
	case NWIF_ETHER_IFACE_TYPE:
		sess.err = nwif_conf_clui_clear_ether(
			nwif_ether_conf_from_iface(conf), &ctx->iface_attrs);
		if (sess.err) {
			clui_err(parser,
			         "failed to clear '%s' ethernet interface "
			         "attribute(s): unexpected attribute(s).",
			         ctx->iface_name);
		}
		break;
#endif /* defined(CONFIG_NWIF_ETHER) */

	default:
		nwif_ui_assert(0);
	}

	if (sess.err)
		goto destroy;

	sess.err = nwif_iface_conf_save(conf, &sess.xact);
	if (sess.err)
		nwif_conf_clui_err(parser,
		                   sess.err,
		                   "failed to save '%s' interface",
		                   ctx->iface_name);

destroy:
	nwif_iface_conf_destroy(conf);

end:
	nwif_conf_clui_end_session(&sess);

close:
	return nwif_conf_clui_close_session(&sess);
}

static int
nwif_conf_clui_parse_clear_iface(const struct clui_cmd *cmd,
                                 struct clui_parser    *parser,
                                 int                    argc,
                                 char * const           argv[],
                                 void                  *ctx)
{
	nwif_ui_assert(ctx);

	struct nwif_conf_clui_ctx *nctx = (struct nwif_conf_clui_ctx *)ctx;
	nwif_conf_clui_exec_fn    *exec;
	int                        ret;

	if (argc < 1) {
		clui_err(parser, "missing arguments.\n");
		goto help;
	}

	if (!strcmp(argv[0], "help")) {
		nwif_conf_clui_sched_help(ctx, cmd);
		return 0;
	}

	if (argc < 2 || argc > 9) {
		clui_err(parser, "invalid number of arguments.\n");
		goto help;
	}

	ret = nwif_ui_parse_conf_id(argv[0], &nctx->iface_id);
	if (!ret) {
		exec = nwif_conf_clui_exec_clear_iface_byid;
		goto attrs;
	}

	ret = nwif_ui_parse_iface_name(argv[0]);
	if (ret > 0) {
		nctx->iface_name = argv[0];
		exec = nwif_conf_clui_exec_clear_iface_byname;
		goto attrs;
	}

	clui_err(parser, "invalid interface name or id '%s'.\n", argv[0]);

	return -EINVAL;

attrs:
	ret = clui_parse_all_switch_parms(
		cmd,
		parser,
		nwif_iface_conf_switch_parms,
		array_nr(nwif_iface_conf_switch_parms),
		argc - 1,
		&argv[1],
		ctx);
	if (ret)
		return ret;

	nwif_conf_clui_sched_exec(ctx, exec);

	return 0;

help:
	clui_help_cmd(cmd, parser, stderr);

	return -EINVAL;
}

static void
nwif_conf_clui_iface_clear_help(const struct clui_cmd    *cmd __unused,
                                const struct clui_parser *parser,
                                FILE                     *stdio)
{
	if (nwif_conf_clui_shell_mode)
		fprintf(stdio, NWIF_CONF_CLUI_IFACE_CLEAR_HELP, "", "");
	else
		fprintf(stdio,
		        NWIF_CONF_CLUI_IFACE_CLEAR_HELP,
		        parser->argv0,
		        " ");
}

static const struct clui_cmd nwif_conf_clui_iface_clear_cmd = {
	.parse = nwif_conf_clui_parse_clear_iface,
	.help  = nwif_conf_clui_iface_clear_help
};

/******************************************************************************
 * iface show command handling
 ******************************************************************************/

#define NWIF_CONF_CLUI_IFACE_SHOW_HELP \
	"Synopsis:\n" \
	"    %1$s%2$siface show <IFACE_ID>\n" \
	"    %1$s%2$siface show <IFACE_NAME>\n" \
	"    Show attributes of interface specified by <IFACE_ID> or <IFACE_NAME>.\n" \
	"\n" \
	"    %1$s%2$siface show [all]\n" \
	"    Show attributes of all interfaces.\n" \
	"\n" \
	"    %1$s%2$siface show help\n" \
	"    This help message.\n" \
	"\n" \
	"Where:\n" \
	NWIF_CONF_CLUI_IFACE_ID_WHERE \
	NWIF_CONF_CLUI_IFACE_NAME_WHERE

static int
nwif_conf_clui_show_all_ifaces(struct nwif_conf_clui_session *session)
{
	nwif_ui_assert_session(session);

	const struct kvs_table  *ifaces;
	struct kvs_iter          iter;
	struct libscols_table   *tbl;
	uint64_t                 id;
        struct kvs_chunk         item;
	int                      err;

	ifaces = nwif_conf_get_iface_table(session->repo);

	err = nwif_iface_conf_init_iter(ifaces, &session->xact, &iter);
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
		struct nwif_iface_conf *conf;

		conf = nwif_iface_conf_create_from_rec(ifaces, id, &item);
		if (!conf) {
			err = -errno;
			break;
		}

		err = nwif_ui_render_iface_conf_table(tbl, conf);

		nwif_iface_conf_destroy(conf);
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

	err = nwif_conf_clui_open_session(&sess, ctx->path, parser);
	if (err)
		return err;

	if (nwif_conf_clui_begin_session(&sess))
		goto close;

	nwif_conf_clui_show_all_ifaces(&sess);

	nwif_conf_clui_end_session(&sess);

close:
	return nwif_conf_clui_close_session(&sess);
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

	iface = nwif_iface_conf_create_byname(
		nwif_conf_get_iface_table(session->repo),
		&session->xact,
		name,
		strlen(name));
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

	err = nwif_conf_clui_open_session(&sess, ctx->path, parser);
	if (err)
		return err;

	if (nwif_conf_clui_begin_session(&sess))
		goto close;

	sess.err = nwif_conf_clui_show_iface_byname(&sess, ctx->iface_name);

	nwif_conf_clui_end_session(&sess);

close:
	return nwif_conf_clui_close_session(&sess);
}

static int
nwif_conf_clui_show_iface_byid(struct nwif_conf_clui_session *session,
                               uint64_t                       id)
{
	struct nwif_iface_conf *iface;
	int                     ret;

	iface = nwif_iface_conf_create_byid(
		nwif_conf_get_iface_table(session->repo),
		&session->xact,
		id);
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

	err = nwif_conf_clui_open_session(&sess, ctx->path, parser);
	if (err)
		return err;

	if (nwif_conf_clui_begin_session(&sess))
		goto close;

	sess.err = nwif_conf_clui_show_iface_byid(&sess, ctx->iface_id);

	nwif_conf_clui_end_session(&sess);

close:
	return nwif_conf_clui_close_session(&sess);
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
	if (nwif_conf_clui_shell_mode)
		fprintf(stdio, NWIF_CONF_CLUI_IFACE_SHOW_HELP, "", "");
	else
		fprintf(stdio,
		        NWIF_CONF_CLUI_IFACE_SHOW_HELP,
		        parser->argv0,
		        " ");
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
	"    %1$s%2$siface del <IFACE_ID>\n" \
	"    Delete interface specified by <IFACE_ID>.\n" \
	"\n" \
	"    %1$s%2$siface del <IFACE_NAME>\n" \
	"    Delete interface specified by <IFACE_NAME>.\n" \
	"\n" \
	"    %1$s%2$siface del help\n" \
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

	err = nwif_conf_clui_open_session(&sess, ctx->path, parser);
	if (err)
		return err;

	if (nwif_conf_clui_begin_session(&sess))
		goto close;

	sess.err = nwif_iface_conf_del_byid(
		nwif_conf_get_iface_table(sess.repo),
		&sess.xact,
		ctx->iface_id);
	if (sess.err) {
		char str[NWIF_CONF_ID_STRING_MAX];

		nwif_ui_sprintf_conf_id(str, ctx->iface_id);
		nwif_conf_clui_err(parser,
		                   sess.err,
		                   "failed to delete interface identified by "
		                   "'%s'",
		                   str);
	}

	nwif_conf_clui_end_session(&sess);

close:
	return nwif_conf_clui_close_session(&sess);
}

static int
nwif_conf_clui_exec_del_iface_byname(const struct nwif_conf_clui_ctx *ctx,
                                     const struct clui_parser        *parser)
{
	nwif_ui_assert(ctx);

	struct nwif_conf_clui_session sess;
	int                           err;

	err = nwif_conf_clui_open_session(&sess, ctx->path, parser);
	if (err)
		return err;

	if (nwif_conf_clui_begin_session(&sess))
		goto close;

	sess.err = nwif_iface_conf_del_byname(
		nwif_conf_get_iface_table(sess.repo),
		&sess.xact,
		ctx->iface_name,
		strlen(ctx->iface_name));
	if (sess.err) {
		char str[NWIF_CONF_ID_STRING_MAX];

		nwif_ui_sprintf_conf_id(str, ctx->iface_id);
		nwif_conf_clui_err(parser,
		                   sess.err,
		                   "failed to delete interface '%s'",
		                   ctx->iface_name);
	}

	nwif_conf_clui_end_session(&sess);

close:
	return nwif_conf_clui_close_session(&sess);
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
	if (nwif_conf_clui_shell_mode)
		fprintf(stdio, NWIF_CONF_CLUI_IFACE_DEL_HELP, "", "");
	else
		fprintf(stdio,
		        NWIF_CONF_CLUI_IFACE_DEL_HELP,
		        parser->argv0,
		        " ");
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
	"    %1$s%2$siface show [IFACE_SHOW_SPEC] | help\n" \
	"    Show attributes of interface according to [IFACE_SHOW_SPEC].\n" \
	"\n" \
	"    %1$s%2$siface new <IFACE_NEW_SPEC> | help\n" \
	"    Create new interface according to <IFACE_NEW_SPEC>.\n" \
	"\n" \
	"    %1$s%2$siface set <IFACE_SET_SPEC> | help\n" \
	"    Setup interface attributes according to <IFACE_SET_SPEC>.\n" \
	"\n" \
	"    %1$s%2$siface clear <IFACE_CLEAR_SPEC> | help\n" \
	"    Clear interface attributes according to <IFACE_CLEAR_SPEC>.\n" \
	"\n" \
	"    %1$s%2$siface del <IFACE_DEL_SPEC> | help\n" \
	"    Delete interface according to <IFACE_DEL_SPEC>.\n" \
	"\n" \
	"    %1$s%2$siface help\n" \
	"    This help message.\n" \
	"\n" \
	"Where:\n" \
	"    [IFACE_SHOW_SPEC]  -- optional show interface specification.\n" \
	"    <IFACE_NEW_SPEC>   -- mandatory interface creation specification.\n" \
	"    <IFACE_SET_SPEC>   -- mandatory interface setup specification.\n" \
	"    <IFACE_CLEAR_SPEC> -- mandatory interface clear specification.\n" \
	"    <IFACE_DEL_SPEC>   -- mandatory interface deletion specification.\n"

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
	if (nwif_conf_clui_shell_mode)
		fprintf(stdio, NWIF_CONF_CLUI_IFACE_HELP, "", "");
	else
		fprintf(stdio, NWIF_CONF_CLUI_IFACE_HELP, parser->argv0, " ");
}

static const struct clui_cmd nwif_conf_clui_iface_cmd = {
	.parse = nwif_conf_clui_parse_iface,
	.help  = nwif_conf_clui_iface_help
};

/******************************************************************************
 * Shell command
 ******************************************************************************/

#define NWIF_CONF_CLUI_SHELL_HELP \
	"Synopsis:\n" \
	"    iface <IFACE_CMD> | help\n" \
	"    Perform interface(s) operation according to <IFACE_CMD> command.\n" \
	"\n" \
	"    quit\n" \
	"    Quit interactive shell.\n" \
	"\n" \
	"    help\n" \
	"    This help message.\n" \

static void
nwif_conf_clui_shell_cmd_help(const struct clui_cmd    *cmd __unused,
                              const struct clui_parser *parser __unused,
                              FILE                     *stdio)
{
	fprintf(stdio, NWIF_CONF_CLUI_SHELL_HELP);
}

static int
nwif_conf_clui_parse_shell(const struct clui_cmd *cmd,
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
	if (!strcmp(argv[0], "quit")) {
		return -ESHUTDOWN;
	}
	else if (!strcmp(argv[0], "help")) {
		nwif_conf_clui_sched_help(ctx, cmd);
		return 0;
	}
	else
		clui_err(parser, "unknown '%s' command.\n", argv[0]);

help:
	clui_help_cmd(cmd, parser, stderr);

	return -EINVAL;
}

static const struct clui_cmd nwif_conf_clui_shell_cmd = {
	.parse = nwif_conf_clui_parse_shell,
	.help  = nwif_conf_clui_shell_cmd_help
};

/******************************************************************************
 * Top-level command
 ******************************************************************************/

#define NWIF_CONF_CLUI_TOP_HELP \
	"Usage:\n" \
	"    %1$s -- Manage nwif configuration.\n" \
	"\n" \
	"Synopsis:\n" \
	"    %1$s shell\n" \
	"    Run in interactive shell mode.\n" \
	"\n" \
	"    %1$s[OPTIONS] iface <IFACE_CMD> | help\n" \
	"    Perform interface(s) operation according to <IFACE_CMD> command.\n" \
	"\n" \
	"    %1$s help\n" \
	"    This help message.\n" \
	"\n" \
	"With [OPTIONS]:\n" \
	"    -d | --dbdir <DBDIR_PATH> use DBDIR_PATH as pathname to configuration\n" \
	"                              database directory.\n"

static void
nwif_conf_clui_top_cmd_help(const struct clui_cmd    *cmd __unused,
                            const struct clui_parser *parser,
                            FILE                     *stdio)
{
	fprintf(stdio, NWIF_CONF_CLUI_TOP_HELP, parser->argv0);
}

static int
nwif_conf_clui_parse_top(const struct clui_cmd *cmd,
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
	else if ((argc == 1) && !strcmp(argv[0], "shell")) {
		if (!isatty(STDIN_FILENO)) {
			nwif_conf_clui_err(parser,
			                   -ENOTTY,
			                   "cannot run in shell mode\n");
			return -ENOTTY;
		}

		nwif_conf_clui_shell_mode = true;
		return 0;
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

static const struct clui_cmd nwif_conf_clui_top_cmd = {
	.parse = nwif_conf_clui_parse_top,
	.help  = nwif_conf_clui_top_cmd_help
};

static void
nwif_conf_clui_opts_help(const struct clui_parser *parser,
                         FILE                     *stdio)
{
	fprintf(stdio, NWIF_CONF_CLUI_TOP_HELP, parser->argv0);
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

static void
nwif_conf_clui_handle_sig(int signo __unused)
{
	clui_shell_shutdown();
}

static void
nwif_conf_clui_init_sigs(void)
{
	sigset_t         sigs;
	struct sigaction act = {
		.sa_handler = nwif_conf_clui_handle_sig,
		.sa_flags   = 0
	};

	usig_emptyset(&sigs);
	usig_addset(&sigs, SIGHUP);
	usig_addset(&sigs, SIGINT);
	usig_addset(&sigs, SIGQUIT);
	usig_addset(&sigs, SIGTERM);

	act.sa_mask = sigs;
	usig_action(SIGHUP, &act, NULL);
	usig_action(SIGINT, &act, NULL);
	usig_action(SIGQUIT, &act, NULL);
	usig_action(SIGTERM, &act, NULL);
}

int
main(int argc, char * const argv[])
{
	struct clui_parser        parser;
	struct nwif_conf_clui_ctx ctx = { 0, };
	int                       ret;

	setlocale(LC_ALL, "");

	ret = clui_init(&parser, argc, argv);
	if (ret)
		return EXIT_FAILURE;

	ctx.path = CONFIG_NWIF_LOCALSTATEDIR;

	ret = clui_parse_opts(&nwif_conf_clui_opt_set,
	                      &parser,
	                      argc,
	                      argv,
	                      &ctx);
	if (ret < 0)
		return EXIT_FAILURE;

	ret = clui_parse_cmd(&nwif_conf_clui_top_cmd,
	                     &parser,
	                     argc - ret,
	                     &argv[ret],
	                     &ctx);
	if (ret < 0)
		return EXIT_FAILURE;

	if (nwif_conf_clui_shell_mode) {
		nwif_conf_clui_init_sigs();
		clui_shell_init(NWIF_CLUI_CONF_PROMPT, true);

		while (true) {
			struct clui_shell_expr expr;

			ret = clui_shell_read_expr(&expr);
			if (ret == -ESHUTDOWN) {
				/* Shell shutdown requested. */
				ret = 0;
				break;
			}
			else if (ret == -ENODATA) {
				/* Empty input. */
				continue;
			}
			else if (ret) {
				/* Input life fetching error. */
				break;
			}

			nwif_conf_clui_reset_ctx(&ctx);
			ret = clui_parse_cmd(&nwif_conf_clui_shell_cmd,
			                     &parser,
			                     expr.nr,
			                     expr.words,
			                     &ctx);
			if (!ret)
				ctx.exec(&ctx, &parser);

			clui_shell_free_expr(&expr);

			if (ret == -ESHUTDOWN) {
				ret = 0;
				break;
			}
		}
	}
	else
		ret = ctx.exec(&ctx, &parser);

	return !ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
