#ifndef _NWIF_UI_H
#define _NWIF_UI_H

#include <nwif/nwif.h>
#include <sys/types.h>
#include <kvstore/autorec.h>

struct ether_addr;

extern const char *
nwif_ui_get_iface_type_label(enum nwif_iface_type type);

#define NWIF_CONF_ID_STRING_MAX (14U)

extern int
nwif_ui_parse_conf_id(const char *arg, struct kvs_autorec_id *id);

extern void
nwif_ui_sprintf_conf_id(char                  string[NWIF_CONF_ID_STRING_MAX],
                        struct kvs_autorec_id id);

extern ssize_t
nwif_ui_parse_iface_name(const char *arg);

extern int
nwif_ui_parse_oper_state(const char *arg, uint8_t *oper);

extern const char *
nwif_ui_get_oper_state_label(uint8_t oper);

extern int
nwif_ui_parse_mtu(const char *arg, uint32_t *mtu);

extern ssize_t
nwif_ui_normalize_syspath(const char *arg, char **syspath);

extern ssize_t
nwif_ui_resolve_syspath(const char *arg, char **syspath);

extern int
nwif_ui_parse_hwaddr(const char *arg, struct ether_addr *addr);

#endif /* _NWIF_UI_H */
