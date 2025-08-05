package client

import (
	"os"
	"time"

	"github.com/containerd/ttrpc"
	"github.com/sirupsen/logrus"
)

const (
	VSockSocketScheme     = "vsock"
	HybridVSockScheme     = "hvsock"
	RemoteSockScheme      = "remote"
	MockHybridVSockScheme = "mock"
)

var defaultDialTimeout = 30 * time.Second

var hybridVSockPort uint32
var hybridVSockErrors uint32 = 0

const hybridVSockErrorsSkip uint32 = 128

var agentClientFields = logrus.Fields{
	"name":   "agent-client",
	"pid":    os.Getpid(),
	"source": "agent-client",
}

var agentClientLog = logrus.WithFields(agentClientFields)

// AgentClient is an agent gRPC client connection wrapper for agentgrpc.AgentServiceClient
type AgentClient struct {
	AgentServiceClient agentgrpc.AgentServiceService
	HealthClient       agentgrpc.HealthService
	conn               *ttrpc.Client
}
