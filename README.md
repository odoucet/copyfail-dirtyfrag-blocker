# copy-fail AND dirtyfrag Blocker

**This project started as a fork of https://github.com/cozystack/copy-fail-blocker** to add mitigation for [CVE-XXXXX](https://github.com/V4bel/dirtyfrag) ("dirtyfrag").


BPF-LSM mitigation for [CVE-2026-31431](https://copy.fail/) ("Copy Fail") and
[CVE-XXXXX](https://github.com/V4bel/dirtyfrag) ("dirtyfrag") and
similar privilege-escalation vulnerabilities that depend on userspace access
to the Linux kernel crypto API (`AF_ALG` / `algif_*`).

A small DaemonSet attaches a single BPF-LSM program to the `socket_create`
hook on every node. The program returns `-EPERM` for any `socket(AF_ALG, ...)`
call, regardless of process capabilities, namespace, or seccomp profile.

Tested on Talos Linux (which ships with `CONFIG_BPF_LSM=y` and `bpf` in the
default LSM stack since v1.10), works on any distribution with the same
kernel configuration.


## Why

See https://github.com/cozystack/copy-fail-blocker and https://github.com/V4bel/dirtyfrag

## Install

I kept this project simple, just to compile a docker image with the fix.

To deploy on kubernetes, refer to project https://github.com/cozystack/copy-fail-blocker and use the image from this repository instead of theirs.

## Verify

From any pod on a covered node:

```sh
python3 - <<'PY'
import socket

tests = [
    ("AF_ALG", 38, socket.SOCK_SEQPACKET, 0),
    ("AF_RXRPC", 33, socket.SOCK_DGRAM, 0),
    ("NETLINK_XFRM", socket.AF_NETLINK, socket.SOCK_RAW, 6),
]

for name, family, typ, proto in tests:
    try:
        s = socket.socket(family, typ, proto)
        s.close()
        print(f"FAIL: {name} authorized")
    except OSError as e:
        print(f"OK: {name} blocked or unavailable: errno={e.errno} {e}")
PY
```

Expected output (OK for all three lines):

```
OK: AF_ALG blocked or unavailable: errno=1 [Errno 1] Operation not permitted
OK: AF_RXRPC blocked or unavailable: errno=1 [Errno 1] Operation not permitted
OK: NETLINK_XFRM blocked or unavailable: errno=1 [Errno 1] Operation not permitted
```

The script must run as a **non-root user** — root is intentionally allowed through
(see [Limitations](#limitations)).

### Kubernetes Job

A ready-to-use Job is provided in [`testjob.yaml`](testjob.yaml). It runs as
UID 1000 and exits with code 1 if any socket is not blocked:

```sh
kubectl apply -f testjob.yaml
kubectl wait --for=condition=complete job/copyfail-dirtyfrag-test --timeout=60s
kubectl logs job/copyfail-dirtyfrag-test
```

## Build

```sh
make image REGISTRY=myregistry.example.com TAG=v1.0
docker push myregistry.example.com/copyfail:v1.0
```

## Known legitimate users of the blocked socket families

Deploying this blocker may break software that legitimately uses these socket
families. Audit your nodes before deploying.

| Socket | Legitimate users | Risk |
|--------|-----------------|------|
| `AF_ALG` | `cryptsetup` / LUKS, OpenSSL with `af_alg` engine, `libkcapi` | Low on Kubernetes nodes — disk encryption is handled at the host level, not inside pods |
| `AF_RXRPC` | `OpenAFS` / `kafs` (Andrew File System) | Very low — AFS is rare in modern environments |
| `NETLINK_XFRM` | `strongSwan`, `Libreswan`, `ip xfrm` (iproute2), **Calico with IPsec**, **Cilium with IPsec** | **High if your CNI uses IPsec for pod-to-pod encryption** — this will break it |

In practice, `AF_RXRPC` is safe to block everywhere. `NETLINK_XFRM` is the
most impactful: if your cluster uses a CNI in IPsec mode (Calico, Cilium),
do not deploy this blocker without disabling the `NETLINK_XFRM` rule first.

## Limitations

- **The hook lives only while the pod runs.** On pod restart there is a
  short window (seconds) where `AF_ALG` is reachable again. For most
  threat models this is acceptable; if not, consider pinning the BPF link
  to bpffs (not implemented here — see [issues](https://github.com/odoucet/copyfail-dirtyfrag-blocker/issues)).
- **Anyone with `CAP_BPF` and `CAP_SYS_ADMIN`** on the host can detach the
  hook. This is not a substitute for cluster-wide privilege restrictions.
- **Does not block `algif_skcipher` / `algif_hash` / etc.** The program
  rejects the entire `AF_ALG` family, but only `algif_aead` is currently
  known to be exploitable. If a future CVE needs a finer filter (e.g. hook
  `bind()` and inspect `salg_type`), this is straightforward to add.
- **No effect on processes that already hold an open `AF_ALG` socket.**
  Existing sockets keep working until closed.
- **Root bypass is unsafe with Kubernetes user namespace remapping.**
  The hook allows root (UID 0) through to preserve compatibility with
  system daemons (Cilium, strongSwan). However, `bpf_get_current_uid_gid()`
  returns the UID in the *task's own user namespace*, not the host namespace.
  On clusters with user namespace remapping enabled (Kubernetes ≥ 1.30,
  opt-in), a container whose in-namespace UID is 0 but whose host UID is
  non-zero will pass this check unblocked — and can still exploit these CVEs
  to reach host root via kernel code execution. User namespaces do not
  protect against kernel exploits. The proper fix is to read the host UID
  via BPF CO-RE (`task->cred->uid.val`) instead of
  `bpf_get_current_uid_gid()`, but this requires `vmlinux` BTF and is not
  yet implemented. **Do not rely on this blocker as the sole mitigation on
  clusters with user namespace remapping enabled.**

## License

Apache License 2.0 — see [LICENSE](LICENSE).
