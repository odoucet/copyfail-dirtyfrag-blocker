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

### kubectl

For the latest commit on `main` (may include unreleased changes):

```sh
kubectl apply -f https://raw.githubusercontent.com/odoucet/copyfail-dirtyfrag-blocker/refs/heads/main/manifests/copy-fail-blocker.yaml
```

### Helm

The chart is not published as an OCI artifact (the registry path is shared
with the container image). Install from a tagged checkout:

```sh
git clone  https://github.com/odoucet/copyfail-dirtyfrag-blocker
cd copyfail-dirtyfrag-blocker
helm upgrade --install copy-fail-blocker charts/copy-fail-blocker \
  --namespace kube-system
```

Or via the Makefile shortcuts:

```sh
make apply         # helm upgrade --install into kube-system
make diff          # preview changes against the cluster
make delete        # uninstall
make manifest      # regenerate manifests/copy-fail-blocker.yaml
```

The DaemonSet must run privileged (it loads BPF programs and writes to
bpffs). Place it in a namespace with the privileged Pod Security Standard,
or in `kube-system`, which is privileged by default.

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
        print(f"FAIL: {name} autorisé")
    except OSError as e:
        print(f"OK: {name} bloqué ou indisponible: errno={e.errno} {e}")
PY
```

Expected output:

```
OK: [Errno 1] Operation not permitted
```

## Build

```sh
make image                                       # docker buildx build + push
make image REGISTRY=ghcr.io/myorg TAG=v0.2.1     # custom tag
make image PUSH=0 LOAD=1                         # build locally without pushing
```

`make image` updates `charts/copy-fail-blocker/values.yaml` with the
resolved image digest so the chart always pins by digest.

Build dependencies live in the Containerfile (clang, libbpf-dev, Go). Local
host needs only `docker buildx`, `helm`, `yq` (mikefarah), `kubectl`, and
`helm-diff`.

## Configuration

`charts/copy-fail-blocker/values.yaml`:

| Key                   | Default                              | Notes                                  |
| --------------------- | ------------------------------------ | -------------------------------------- |
| `image.repository`    | `docker.io/oxeva/copyfail`           | Auto-updated by `make image`           |
| `image.tag`           | `1.0@sha256:...`                     | Pinned by digest                       |
| `priorityClassName`   | `system-node-critical`               | Ensures the daemon survives evictions  |
| `tolerations`         | `[{operator: Exists}]`               | Runs on every node, including tainted  |
| `resources.requests`  | `5m CPU / 16Mi memory`               | Idle footprint after attach            |

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

## License

Apache License 2.0 — see [LICENSE](LICENSE).
