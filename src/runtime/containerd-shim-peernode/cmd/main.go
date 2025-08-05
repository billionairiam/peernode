package main

import (
	"context"

	"github.com/containerd/containerd/v2/cmd/containerd-shim-runc-v2/manager"
	_ "github.com/containerd/containerd/v2/cmd/containerd-shim-runc-v2/task/plugin"
	"github.com/containerd/containerd/v2/pkg/shim"
)

func main() {
	shim.Run(context.Background(), manager.NewShimManager("io.containerd.runc.v2"))
}
