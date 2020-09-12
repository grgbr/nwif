#include "nwif/config.h"
#include "ui.h"
#include <nwif/conf.h>
#include <stdio.h>
#include <utils/net.h>
#include <linux/if.h>
#include <netinet/ether.h>

#if defined(CONFIG_NWIF_ETHER)
#include <nwif/ether.h>
#endif /* defined(CONFIG_NWIF_ETHER) */

const char *
nwif_ui_get_iface_type_label(enum nwif_iface_type type)
{
	switch (type) {
	case NWIF_ETHER_IFACE_TYPE:
		return "ether";
	default:
		return "unknown";
	}
}

/*
 * Parse a kvs_autorec_id according to the following format: 'XXXXXXXX.xxxx'
 *
 * Where X and x are hexadecimal digits. There can be up to a maximum of 8 X
 * and 4 x digits (separated by a single dot).
 */
int
nwif_ui_parse_conf_id(const char *arg, struct kvs_autorec_id *id)
{
	int     err;
	char    str[NWIF_CONF_ID_STRING_MAX];
	ssize_t len;

	len = ustr_parse(arg, sizeof(str));
	if (!len)
		return -ENODATA;
	if (len < 0)
		return len;

	memcpy(str, arg, len);
	str[len] = '\0';

	len = ustr_skip_notchar(str, '.', len);
	if (!len || ((size_t)len >= (sizeof(str) - 2)))
		return -EBADMSG;

	str[len] = '\0';

	err = ustr_parse_x32(str, &id->rid.pgno);
	if (err)
		return err;

	err = ustr_parse_x16(&str[len + 1], &id->rid.indx);
	if (err)
		return err;

	if (!kvs_autorec_id_isok(*id))
		return -EPERM;

	return 0;
}

void
nwif_ui_sprintf_conf_id(char                  string[NWIF_CONF_ID_STRING_MAX],
                        struct kvs_autorec_id id)
{
	sprintf(string, "%" PRIx32 ".%04" PRIx16, id.rid.pgno, id.rid.indx);
}

ssize_t
nwif_ui_parse_iface_name(const char *arg)
{
	nwif_ui_assert(arg);

	return unet_check_iface_name(arg);
}

static const char *nwif_ui_oper_state_labels[] = {
	[IF_OPER_UNKNOWN]        = "unknown",
	[IF_OPER_NOTPRESENT]     = "absent",
	[IF_OPER_DOWN]           = "down",
	[IF_OPER_LOWERLAYERDOWN] = "lowerdown",
	[IF_OPER_TESTING]        = "testing",
	[IF_OPER_DORMANT]        = "dormant",
	[IF_OPER_UP]             = "up"
};

int
nwif_ui_parse_oper_state(const char *arg, uint8_t *oper)
{
	nwif_ui_assert(arg);

	unsigned int o;

	for (o = 0; o < array_nr(nwif_ui_oper_state_labels); o++)
		if (!strcmp(arg, nwif_ui_oper_state_labels[o]))
			break;

	if (o == array_nr(nwif_ui_oper_state_labels))
		return -ENOENT;

	if (!nwif_iface_oper_state_isok(o))
		return -EPERM;

	*oper = (uint8_t)o;

	return 0;
}

const char *
nwif_ui_get_oper_state_label(uint8_t oper)
{
	if (oper < array_nr(nwif_ui_oper_state_labels))
		return nwif_ui_oper_state_labels[oper];

	return nwif_ui_oper_state_labels[IF_OPER_UNKNOWN];
}

int
nwif_ui_parse_mtu(const char *arg, uint32_t *mtu)
{
	nwif_ui_assert(arg);
	nwif_ui_assert(mtu);

	int err;

	err = ustr_parse_uint32(arg, mtu);
	if (err)
		return err;

	if (!unet_mtu_isok(*mtu))
		return -ERANGE;

	return 0;
}

ssize_t
nwif_ui_normalize_syspath(const char *arg, char **syspath)
{
	return unet_normalize_iface_syspath(arg, syspath);
}

ssize_t
nwif_ui_resolve_syspath(const char *arg, char **syspath)
{
	return unet_resolve_iface_syspath(arg, syspath);
}

int
nwif_ui_parse_hwaddr(const char *arg, struct ether_addr *addr)
{
	nwif_ui_assert(arg);
	nwif_ui_assert(addr);

	if (!ether_aton_r(arg, addr))
		return -EINVAL;

	if (unet_hwaddr_is_uaa(addr) || unet_hwaddr_is_mcast(addr))
		return -EPERM;

	return 0;
}

enum nwif_ui_iface_conf_col_id {
	NWIF_UI_IFACE_CONF_ID_CID,
	NWIF_UI_IFACE_CONF_TYPE_CID,
	NWIF_UI_IFACE_CONF_NAME_CID,
	NWIF_UI_IFACE_CONF_OPER_STATE_CID,
	NWIF_UI_IFACE_CONF_MTU_CID,
	NWIF_UI_IFACE_CONF_SYSPATH_CID,
	NWIF_UI_IFACE_CONF_HWADDR_CID,
	NWIF_UI_IFACE_CONF_CID_NR
};

struct nwif_ui_iface_conf_col_desc {
	const char *label;
	double      whint;
	int         flags;
};

static const struct nwif_ui_iface_conf_col_desc
nwif_ui_iface_conf_cols[NWIF_UI_IFACE_CONF_CID_NR] = {
	[NWIF_UI_IFACE_CONF_ID_CID] = {
		.label = "ID",
		.whint = 1.0,
		.flags = SCOLS_FL_RIGHT
	},
	[NWIF_UI_IFACE_CONF_TYPE_CID] = {
		.label = "TYPE",
		.whint = 1.0,
		.flags = 0
	},
	[NWIF_UI_IFACE_CONF_NAME_CID] = {
		.label = "NAME",
		.whint = 1.0,
		.flags = 0
	},
	[NWIF_UI_IFACE_CONF_OPER_STATE_CID] = {
		.label = "OPER",
		.whint = 1.0,
		.flags = 0
	},
	[NWIF_UI_IFACE_CONF_MTU_CID] = {
		.label = "MTU",
		.whint = 1.0,
		.flags = 0
	},
	[NWIF_UI_IFACE_CONF_SYSPATH_CID] = {
		.label = "SYSPATH",
		.whint = 1.0,
		.flags = SCOLS_FL_WRAP
	},
	[NWIF_UI_IFACE_CONF_HWADDR_CID] = {
		.label = "HWADDR",
		.whint = 1.0,
		.flags = 0
	}
};

#if defined(CONFIG_NWIF_ETHER)

static int
nwif_ui_render_ether_conf(struct libscols_line         *line,
                          const struct nwif_iface_conf *iface)
{
	const struct nwif_ether_conf *conf = nwif_ether_conf_from_iface(iface);
	int                           err;
	const struct ether_addr      *hwaddr;

	/* Render sysfs device path. */
	err = scols_line_set_data(line,
	                          NWIF_UI_IFACE_CONF_SYSPATH_CID,
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
		                            NWIF_UI_IFACE_CONF_HWADDR_CID,
		                            str);
		nwif_ui_assert(!err);
	}

	return 0;
}

#else /* !defined(CONFIG_NWIF_ETHER) */

static inline int
nwif_ui_render_ether_conf(struct libscols_line         *line __unused,
                          const struct nwif_iface_conf *iface __unused)
{
	return -ENOSYS;
}

#endif /* defined(CONFIG_NWIF_ETHER) */

int
nwif_ui_render_iface_conf_table(struct libscols_table        *table,
                                const struct nwif_iface_conf *iface)
{
	nwif_ui_assert(table);
	nwif_ui_assert(iface);

	struct libscols_line         *line;
	char                          str[NWIF_CONF_ID_STRING_MAX];
	int                           err;
	enum nwif_iface_type          type;
	const char                   *name;
	uint8_t                       oper;
	uint32_t                      mtu;

	line = scols_table_new_line(table, NULL);
	if (!line)
		return -errno;

	/* Render interface config id. */
	nwif_ui_sprintf_conf_id(str, nwif_iface_conf_get_id(iface));
	err = scols_line_set_data(line, NWIF_UI_IFACE_CONF_ID_CID, str);
	nwif_ui_assert(!err);

	/* Render interface type. */
	type = nwif_iface_conf_get_type(iface);
	err = scols_line_set_data(line,
	                          NWIF_UI_IFACE_CONF_TYPE_CID,
	                          nwif_ui_get_iface_type_label(type));
	if (err)
		return err;

	/* Render optional interface name */
	name = nwif_iface_conf_get_name(iface);
	if (name) {
		err = scols_line_set_data(line,
		                          NWIF_UI_IFACE_CONF_NAME_CID,
		                          name);
		if (err)
			return err;
	}

	/* Render optional operational state. */
	nwif_iface_conf_get_oper_state(iface, &oper);
	err = scols_line_set_data(line,
	                          NWIF_UI_IFACE_CONF_OPER_STATE_CID,
	                          nwif_ui_get_oper_state_label(oper));
	if (err)
		return err;

	/* Render optional MTU. */
	err = nwif_iface_conf_get_mtu(iface, &mtu);
	if (!err) {
		sprintf(str, "%" PRIu16, mtu);
		err = scols_line_set_data(line,
		                          NWIF_UI_IFACE_CONF_MTU_CID,
		                          str);
		nwif_ui_assert(!err);
	}

	/* Now render interface type specific infos. */
	switch (type) {
#if defined(CONFIG_NWIF_ETHER)
	case NWIF_ETHER_IFACE_TYPE:
		return nwif_ui_render_ether_conf(line, iface);
#endif /* defined(CONFIG_NWIF_ETHER) */

	default:
		nwif_ui_assert(0);
	}

	unreachable();
}

struct libscols_table *
nwif_ui_create_iface_conf_table(void)
{
	struct libscols_table *tbl;
	unsigned int           c;

	tbl = scols_new_table();
	if (!tbl)
		return NULL;

	scols_table_enable_header_repeat(tbl, 1);

	for (c = 0; c < array_nr(nwif_ui_iface_conf_cols); c++) {
		const struct nwif_ui_iface_conf_col_desc *col;

		col = &nwif_ui_iface_conf_cols[c];
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
