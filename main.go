// SPDX-License-Identifier: Apache-2.0
//
// copy-fail-blocker loads a single BPF-LSM hook on socket_create that
// returns -EPERM whenever AF_ALG sockets are requested. This neutralizes
// the attack surface for CVE-2026-31431 ("Copy Fail") and any future
// vulnerability that depends on userspace access to algif_* kernel
// crypto API submodules.

package main

import (
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -go-package main blocker bpf/blocker.c -- -O1 -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu -I/usr/include

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	objs := blockerObjects{}
	if err := loadBlockerObjects(&objs, nil); err != nil {
		log.Fatalf("load BPF objects: %v", err)
	}
	defer objs.Close()

	lnk, err := link.AttachLSM(link.LSMOptions{
		Program: objs.BlockDangerousSockets,
	})
	if err != nil {
		log.Fatalf("attach LSM hook: %v", err)
	}
	defer func() {
		if err := lnk.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			log.Printf("close link: %v", err)
		}
	}()

	log.Println("BPF-LSM hook attached: blocking AF_ALG, AF_RXRPC and NETLINK_XFRM")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Println("shutting down, detaching hook")
}