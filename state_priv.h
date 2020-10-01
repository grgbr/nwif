#ifndef _NWIF_STATE_PRIV_H
#define _NWIF_STATE_PRIV_H

#include "common.h"
#include <nlink/work.h>

struct nwif_state_sock;
struct nlink_iface;

typedef int (nwif_state_handle_iface_event_fn)(struct nwif_state_sock   *sock,
                                               const struct nlink_iface *attrs,
                                               void                     *data);

struct nwif_state_ops {
	nwif_state_handle_iface_event_fn *handle_iface_event;
};

#define nwif_state_assert_ops(_ops) \
	nwif_assert(_ops); \
	nwif_assert((_ops)->handle_iface_event)

struct nwif_state_work {
	struct nlink_work   nlink;
	nlink_parse_msg_fn *done;
};

struct nwif_state_sock {
	struct nlink_sock            nlink;
	struct nlmsghdr             *msg;
	struct nlink_win             recv_win;
	const struct nwif_state_ops *ops;
	void                        *data;
	struct nwif_state_work       works[NWIF_CLASS_NR];
};

#define nwif_state_assert_sock(_sock) \
	nwif_assert(_sock); \
	nlink_assert_sock(&(_sock)->nlink); \
	nwif_assert((_sock)->msg); \
	nwif_state_assert_ops((_sock)->ops)

extern int
nwif_state_start_xfer(struct nwif_state_sock *sock,
                      const struct nlmsghdr  *request,
                      nlink_parse_msg_fn     *done);

extern int
nwif_state_start_load(struct nwif_state_sock *sock);

extern void
nwif_state_cancel(struct nwif_state_sock *sock);

extern int
nwif_state_process_events(struct nwif_state_sock *sock);

extern int
nwif_state_open(struct nwif_state_sock      *sock,
                const struct nwif_state_ops *ops,
                void                        *data);

extern void
nwif_state_close(struct nwif_state_sock *sock);

#endif /* _NWIF_STATE_PRIV_H */
