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
	    int kern)
{
	/* Allow host-root processes: legitimate system daemons (Cilium/Calico
	 * IPsec, strongSwan) run as UID 0 and need these socket families.
	 * The exploits only provide value to unprivileged processes seeking
	 * privilege escalation.
	 *
	 * WARNING — user namespace remapping: bpf_get_current_uid_gid()
	 * returns the UID translated into the task's own user namespace, NOT
	 * the initial (host) user namespace. On clusters with user namespace
	 * remapping enabled (Kubernetes ≥ 1.30 opt-in), a container whose
	 * in-namespace UID is 0 but whose host UID is non-zero will still
	 * pass this check — and that container CAN use these CVEs to reach
	 * host root via kernel code execution. User namespaces do not prevent
	 * kernel exploits. To close this gap the host UID must be read via
	 * BPF CO-RE (task->cred->uid.val), which requires vmlinux BTF. This
	 * cluster does not use user namespace remapping, so the current check
	 * is sufficient, but the limitation must be understood. */
	if ((__u32)bpf_get_current_uid_gid() == 0)
		return 0;

	if (family == AF_ALG)      /* Copy-Fail */
		return -EPERM;
	if (family == AF_RXRPC)    /* DirtyFrag RxRPC path */
		return -EPERM;
	if (family != AF_NETLINK)
		return 0;
	if (protocol == NETLINK_XFRM) /* DirtyFrag xfrm-ESP path */
		return -EPERM;
	return 0;
}