package main

import (
	"context"

	"github.com/billionairiam/peernode/src/runtime/containerd-shim-peernode/manager"
	_ "github.com/billionairiam/peernode/src/runtime/containerd-shim-peernode/task/plugin"
	"github.com/containerd/containerd/v2/pkg/shim"
)

func main() {
	shim.Run(context.Background(), manager.NewShimManager("io.containerd.runc.v2"))
}
