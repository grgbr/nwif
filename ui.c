#include "ui.h"
#include "common.h"
#include <stdio.h>
#include <netinet/ether.h>
#include <linux/if.h>
#include <utils/net.h>

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
	nwif_assert(arg);

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
	nwif_assert(arg);

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
	nwif_assert(arg);
	nwif_assert(mtu);

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
	nwif_assert(arg);
	nwif_assert(addr);

	if (!ether_aton_r(arg, addr))
		return -EINVAL;

	if (unet_hwaddr_is_uaa(addr) || unet_hwaddr_is_mcast(addr))
		return -EPERM;

	return 0;
}
