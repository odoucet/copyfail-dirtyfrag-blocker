//go:build ignore

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef AF_ALG
#define AF_ALG 38
#endif

#ifndef AF_RXRPC
#define AF_RXRPC 33
#endif

#ifndef AF_NETLINK
#define AF_NETLINK 16
#endif

#ifndef NETLINK_XFRM
#define NETLINK_XFRM 6
#endif

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/socket_create")
int BPF_PROG(block_dangerous_sockets,
	    int family,
	    int type,
	    int protocol,
	    int kern,
	    int ret)
{
	if (ret)
		return ret;

	/* Copy-Fail mitigation */
	if (family == AF_ALG)
		return -EPERM;

	/* DirtyFrag RxRPC path mitigation */
	if (family == AF_RXRPC)
		return -EPERM;

	/* DirtyFrag xfrm-ESP path mitigation */
	if (family == AF_NETLINK && protocol == NETLINK_XFRM)
		return -EPERM;

	return 0;
}