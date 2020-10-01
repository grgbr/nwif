#ifndef _NWIF_UI_H
#define _NWIF_UI_H

#include "common.h"
#include <libsmartcols/libsmartcols.h>
#include <sys/types.h>

#if defined(CONFIG_NWIF_ASSERT)

#include <utils/assert.h>

#define nwif_ui_assert(_expr) \
	uassert("nwif_ui", _expr)

#else  /* !defined(CONFIG_NWIF_ASSERT) */

#define nwif_ui_assert(_expr)

#endif /* defined(CONFIG_NWIF_ASSERT) */

struct ether_addr;
struct nwif_iface_conf;

extern const char *
nwif_ui_get_iface_type_label(enum nwif_iface_type type);

#define NWIF_CONF_ID_STRING_MAX (13U)

extern int
nwif_ui_parse_conf_id(const char *arg, uint64_t *id);

extern void
nwif_ui_sprintf_conf_id(char string[NWIF_CONF_ID_STRING_MAX], uint64_t id);

extern ssize_t
nwif_ui_parse_iface_name(const char *arg);

extern int
nwif_ui_parse_admin_state(const char *arg, uint8_t *state);

extern const char *
nwif_ui_get_admin_state_label(uint8_t state);

extern int
nwif_ui_parse_mtu(const char *arg, uint32_t *mtu);

extern ssize_t
nwif_ui_normalize_syspath(const char *arg, char **syspath);

extern ssize_t
nwif_ui_resolve_syspath(const char *arg, char **syspath);

extern int
nwif_ui_parse_hwaddr(const char *arg, struct ether_addr *addr);

extern int
nwif_ui_render_iface_conf_table(struct libscols_table        *table,
                                const struct nwif_iface_conf *iface);

static inline void
nwif_ui_display_iface_conf_table(struct libscols_table *table)
{
	nwif_ui_assert(table);

	scols_print_table(table);
}

extern struct libscols_table *
nwif_ui_create_iface_conf_table(void);

static inline void
nwif_ui_destroy_iface_conf_table(struct libscols_table *table)
{
	nwif_ui_assert(table);

	scols_unref_table(table);
}

#endif /* _NWIF_UI_H */
