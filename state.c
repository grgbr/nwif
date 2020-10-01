#include "state_priv.h"
#include "iface_priv.h"
#include <utils/thread.h>
#include <fcntl.h>
#include <linux/rtnetlink.h>

static int
nwif_state_parse_newlink(int status, const struct nlmsghdr *msg, void *data)
{
	nwif_assert(msg);
	nwif_state_assert_sock((struct nwif_state_sock *)data);

	int                     err;
	struct nlink_iface      attrs;
	struct nwif_state_sock *sock = data;

	if (status)
		/* TODO: warn user in case of error ? */
		return (status == -ENODATA) ? 0 : status;

	if (msg->nlmsg_type != RTM_NEWLINK)
		return -ENOMSG;

	err = nwif_iface_state_parse_msg(msg, &attrs);
	if (err)
		return err;

	return sock->ops->handle_iface_event(sock, &attrs, sock->data);
}

static int
nwif_state_parse_msg(int status, const struct nlmsghdr *msg, void *data)
{
	nwif_assert(msg);
	nwif_state_assert_sock((struct nwif_state_sock *)data);

	switch (msg->nlmsg_type) {
	case RTM_NEWLINK:
		return nwif_state_parse_newlink(status, msg, data);

	default:
		return -ENOMSG;
	}

	unreachable();
}

int
nwif_state_process_events(struct nwif_state_sock *sock)
{
	nwif_state_assert_sock(sock);

	while (true) {
		struct nlmsghdr   *msg = sock->msg;
		ssize_t            ret;
		struct nlink_work *work;

		ret = nlink_recv_msg(&sock->nlink, msg);
		if (ret < 0) {
			switch (ret) {
			case -EBADMSG:
				/* Received malformed message: drop. */
				/* TODO: log info message ?? */
			case -ESRCH:
				/* Received message containing an invalid port
				 * ID, i.e. not for us: drop.
				 * TODO: log info message ??
				 */
				ret = 0;
				break;

			case -EAGAIN:
				if (!nlink_win_has_work(&sock->recv_win))
					return 0;
				else
					return -EAGAIN;

			default:
				return ret;
			}

			/* Drop. */
			continue;
		}

		if (!msg->nlmsg_pid && !msg->nlmsg_seq) {
			/* Handle kernel notification messages. */
			ret = nlink_parse_msg(msg,
			                      ret,
			                      nwif_state_parse_msg,
			                      sock);
			if (ret == -EINTR)
				return -EINTR;

			/* TODO: warn user in case of error ? */
			continue;
		}

		if (!nlink_win_has_work(&sock->recv_win))
			/* Unexpected message received: drop ! */
			/* TODO: warn user in case of error ? */
			continue;

		work = nlink_win_pull_work(&sock->recv_win, msg->nlmsg_seq);
		if (!work) {
			/*
			 * Failed to find a scheduled work containing the
			 * expected reply message's sequence number: reply is
			 * very likely outdated (or has never been scheduled,
			 * has been canceled...)
			 * Anyway, drop message !
			 */
			continue;
		}

		ret = nlink_parse_msg(msg,
		                      ret,
		                      ((struct nwif_state_work *)work)->done,
		                      sock);
		if (ret == -EINPROGRESS) {
			/*
			 * We are in the middle of a multipart message
			 * processing. Reschedule work so that we can handle it
			 * entirely.
			 */
			nlink_win_resched_work(&sock->recv_win, work);
			continue;
		}

		if (ret == -EINTR) {
			nlink_win_resched_work(&sock->recv_win, work);
			return -EINTR;
		}

		nlink_win_release_work(&sock->recv_win, work);
	}

	return 0;
}

static struct nwif_state_work *
nwif_state_do_start_xfer(struct nwif_state_sock *sock,
                         const struct nlmsghdr  *request,
                         nlink_parse_msg_fn     *done)
{
	nwif_state_assert_sock(sock);
	nwif_assert(request);
	nwif_assert(done);

	struct nwif_state_work *work;
	int                     err;

	work = (struct nwif_state_work *)
	       nlink_win_acquire_work(&sock->recv_win);
	if (!work) {
		errno = ENOBUFS;
		return NULL;
	}

	work->done = done;
	nlink_win_sched_work(&sock->recv_win, &work->nlink, request->nlmsg_seq);

	while (true) {
		err = nlink_send_msg(&sock->nlink, request);
		if (err != -EAGAIN)
			break;

		uthr_yield();
	}

	if (err)
		goto cancel;

	return work;

cancel:
	nlink_win_cancel_work(&sock->recv_win, &work->nlink);
	nlink_win_release_work(&sock->recv_win, &work->nlink);

	errno = -err;
	return NULL;
}

int
nwif_state_start_xfer(struct nwif_state_sock *sock,
                      const struct nlmsghdr  *request,
                      nlink_parse_msg_fn     *done)
{
	struct nwif_state_work *work;

	work = nwif_state_do_start_xfer(sock, request, done);
	if (!work)
		return -errno;

	return 0;
}

int
nwif_state_start_load(struct nwif_state_sock *sock)
{
	nwif_state_assert_sock(sock);

	struct nwif_state_work *work;
	int                     err;

	nlink_iface_setup_dump(sock->msg, &sock->nlink);

	work = nwif_state_do_start_xfer(sock,
	                                sock->msg,
	                                nwif_state_parse_newlink);
	if (!work)
		return -errno;

	err = nlink_join_route_group(&sock->nlink, RTNLGRP_LINK);
	if (err)
		goto cancel;

	return 0;

cancel:
	nlink_win_cancel_work(&sock->recv_win, &work->nlink);
	nlink_win_release_work(&sock->recv_win, &work->nlink);

	return err;
}

void
nwif_state_cancel(struct nwif_state_sock *sock)
{
	nwif_state_assert_sock(sock);

	unsigned int slot = 0;

	while (true) {
		struct nlink_work *work;

		work = nlink_win_drain_work(&sock->recv_win, &slot);
		if (!work)
			break;

		/*
		 * TODO: run / notify drained works to give clients a chance to
		 * release resources ??
		 */

		nlink_win_release_work(&sock->recv_win, work);
	}
}

int
nwif_state_open(struct nwif_state_sock      *sock,
                const struct nwif_state_ops *ops,
                void                        *data)
{
	nwif_assert(sock);
	nwif_state_assert_ops(ops);

	int          err;
	unsigned int w;

	err = nlink_open_route_sock(&sock->nlink, O_NONBLOCK);
	if (err)
		return err;

	sock->msg = nlink_alloc_msg();
	if (!sock->msg) {
		err = -errno;
		goto close;
	}

	err = nlink_win_init(&sock->recv_win, array_nr(sock->works));
	if (err)
		goto free;

	sock->ops = ops;
	sock->data = data;

	for (w = 0; w < array_nr(sock->works); w++)
		nlink_win_register_work(&sock->recv_win, &sock->works[w].nlink);

	return 0;

free:
	nlink_free_msg(sock->msg);

close:
	nlink_close_sock(&sock->nlink);

	return err;
}

void
nwif_state_close(struct nwif_state_sock *sock)
{
	nwif_state_assert_sock(sock);

	nlink_leave_route_group(&sock->nlink, RTNLGRP_LINK);
	nwif_state_cancel(sock);
	nlink_win_fini(&sock->recv_win);
	nlink_free_msg(sock->msg);
	nlink_close_sock(&sock->nlink);
}
