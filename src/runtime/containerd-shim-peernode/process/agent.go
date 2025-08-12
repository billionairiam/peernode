package process

import (
	"context"
	"errors"
	"sync"
	"time"

	grpc "github.com/billionairiam/peernode/src/runtime/containerd-shim-peernode/protocols/agent"
	"github.com/billionairiam/peernode/src/runtime/containerd-shim-peernode/utils/katatrace"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const namespaceKatashim = "node_shim"

var (
	agentRPCDurationsHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespaceKatashim,
		Name:      "agent_rpc_durations_histogram_milliseconds",
		Help:      "RPC latency distributions.",
		Buckets:   prometheus.ExponentialBuckets(1, 2, 10),
	},
		[]string{"action"},
	)
)

type customRequestTimeoutKeyType struct{}

var (
	checkRequestTimeout              = 30 * time.Second
	createContainerRequestTimeout    = 60 * time.Second
	defaultRequestTimeout            = 60 * time.Second
	remoteRequestTimeout             = 300 * time.Second
	customRequestTimeoutKey          = customRequestTimeoutKeyType(struct{}{})
	errorMissingOCISpec              = errors.New("Missing OCI specification")
	defaultKataHostSharedDir         = "/run/kata-containers/shared/sandboxes/"
	defaultKataGuestSharedDir        = "/run/kata-containers/shared/containers/"
	defaultKataGuestNydusRootDir     = "/run/kata-containers/shared/"
	defaultKataGuestVirtualVolumedir = "/run/kata-containers/virtual-volumes/"
	mountGuestTag                    = "kataShared"
	defaultKataGuestSandboxDir       = "/run/kata-containers/sandbox/"
	type9pFs                         = "9p"
	typeVirtioFS                     = "virtiofs"
	typeOverlayFS                    = "overlay"
	kata9pDevType                    = "9p"
	kataMmioBlkDevType               = "mmioblk"
	kataBlkDevType                   = "blk"
	kataBlkCCWDevType                = "blk-ccw"
	kataSCSIDevType                  = "scsi"
	kataNvdimmDevType                = "nvdimm"
	kataVirtioFSDevType              = "virtio-fs"
	kataOverlayDevType               = "overlayfs"
	kataWatchableBindDevType         = "watchable-bind"
	kataVfioPciDevType               = "vfio-pci"     // VFIO PCI device to used as VFIO in the container
	kataVfioPciGuestKernelDevType    = "vfio-pci-gk"  // VFIO PCI device for consumption by the guest kernel
	kataVfioApDevType                = "vfio-ap"      // VFIO AP device for hot-plugging
	kataVfioApColdDevType            = "vfio-ap-cold" // VFIO AP device for cold-plugging
	sharedDir9pOptions               = []string{"trans=virtio,version=9p2000.L,cache=mmap", "nodev"}
	sharedDirVirtioFSOptions         = []string{}
	sharedDirVirtioFSDaxOptions      = "dax"
	shmDir                           = "shm"
	kataEphemeralDevType             = "ephemeral"
	grpcMaxDataSize                  = int64(1024 * 1024)
	localDirOptions                  = []string{"mode=0777"}
	maxHostnameLen                   = 64
	GuestDNSFile                     = "/etc/resolv.conf"
)

// NodeAgentTracingTags defines tags for the trace span
var NodeAgentTracingTags = map[string]string{
	"source":    "runtime",
	"package":   "task",
	"subsystem": "agent",
}

const (
	grpcCheckRequest                          = "grpc.CheckRequest"
	grpcExecProcessRequest                    = "grpc.ExecProcessRequest"
	grpcCreateSandboxRequest                  = "grpc.CreateSandboxRequest"
	grpcDestroySandboxRequest                 = "grpc.DestroySandboxRequest"
	grpcCreateContainerRequest                = "grpc.CreateContainerRequest"
	grpcStartContainerRequest                 = "grpc.StartContainerRequest"
	grpcRemoveContainerRequest                = "grpc.RemoveContainerRequest"
	grpcSignalProcessRequest                  = "grpc.SignalProcessRequest"
	grpcUpdateRoutesRequest                   = "grpc.UpdateRoutesRequest"
	grpcUpdateInterfaceRequest                = "grpc.UpdateInterfaceRequest"
	grpcUpdateEphemeralMountsRequest          = "grpc.UpdateEphemeralMountsRequest"
	grpcRemoveStaleVirtiofsShareMountsRequest = "grpc.RemoveStaleVirtiofsShareMountsRequest"
	grpcListInterfacesRequest                 = "grpc.ListInterfacesRequest"
	grpcListRoutesRequest                     = "grpc.ListRoutesRequest"
	grpcAddARPNeighborsRequest                = "grpc.AddARPNeighborsRequest"
	grpcOnlineCPUMemRequest                   = "grpc.OnlineCPUMemRequest"
	grpcUpdateContainerRequest                = "grpc.UpdateContainerRequest"
	grpcWaitProcessRequest                    = "grpc.WaitProcessRequest"
	grpcTtyWinResizeRequest                   = "grpc.TtyWinResizeRequest"
	grpcWriteStreamRequest                    = "grpc.WriteStreamRequest"
	grpcCloseStdinRequest                     = "grpc.CloseStdinRequest"
	grpcStatsContainerRequest                 = "grpc.StatsContainerRequest"
	grpcPauseContainerRequest                 = "grpc.PauseContainerRequest"
	grpcResumeContainerRequest                = "grpc.ResumeContainerRequest"
	grpcReseedRandomDevRequest                = "grpc.ReseedRandomDevRequest"
	grpcGuestDetailsRequest                   = "grpc.GuestDetailsRequest"
	grpcMemHotplugByProbeRequest              = "grpc.MemHotplugByProbeRequest"
	grpcCopyFileRequest                       = "grpc.CopyFileRequest"
	grpcSetGuestDateTimeRequest               = "grpc.SetGuestDateTimeRequest"
	grpcGetOOMEventRequest                    = "grpc.GetOOMEventRequest"
	grpcGetMetricsRequest                     = "grpc.GetMetricsRequest"
	grpcAddSwapRequest                        = "grpc.AddSwapRequest"
	grpcVolumeStatsRequest                    = "grpc.VolumeStatsRequest"
	grpcResizeVolumeRequest                   = "grpc.ResizeVolumeRequest"
	grpcGetIPTablesRequest                    = "grpc.GetIPTablesRequest"
	grpcSetIPTablesRequest                    = "grpc.SetIPTablesRequest"
	grpcSetPolicyRequest                      = "grpc.SetPolicyRequest"
)

var virtLog = logrus.WithField("source", "virtcontainers")

// NodeAgentState is the structure describing the data stored from this
// agent implementation.
type NodeAgentState struct {
	URL string
}

// nolint: govet
type NodeAgent struct {
	ctx      context.Context
	vmSocket interface{}

	client *AgentClient

	// lock protects the client pointer
	sync.Mutex

	state NodeAgentState

	reqHandlers map[string]reqFunc
	kmodules    []string

	dialTimout uint32

	keepConn bool
	dead     bool
}

type reqFunc func(context.Context, interface{}) (interface{}, error)

func (n *NodeAgent) connect(ctx context.Context) error {
	if n.dead {
		return errors.New("Dead agent")
	}
	// lockless quick pass
	if n.client != nil {
		return nil
	}

	span, _ := katatrace.Trace(ctx, n.Logger(), "connect", NodeAgentTracingTags)
	defer span.End()

	// This is for the first connection only, to prevent race
	n.Lock()
	defer n.Unlock()
	if n.client != nil {
		return nil
	}

	n.Logger().WithField("url", n.state.URL).Info("New client")
	client, err := NewAgentClient(n.ctx, n.state.URL, n.dialTimout)
	if err != nil {
		n.dead = true
		return err
	}

	n.installReqFunc(client)
	n.client = client

	return nil
}

func (n *NodeAgent) disconnect(ctx context.Context) error {
	span, _ := katatrace.Trace(ctx, n.Logger(), "Disconnect", NodeAgentTracingTags)
	defer span.End()

	n.Lock()
	defer n.Unlock()

	if n.client == nil {
		return nil
	}

	if err := n.client.Close(); err != nil && grpcStatus.Convert(err).Code() != codes.Canceled {
		return err
	}

	n.client = nil
	n.reqHandlers = nil

	return nil
}

func (n *NodeAgent) sendReq(spanCtx context.Context, request interface{}) (interface{}, error) {
	start := time.Now()

	if err := n.connect(spanCtx); err != nil {
		return nil, err
	}
	if !n.keepConn {
		defer n.disconnect(spanCtx)
	}

	msgName := string(proto.MessageName(request.(proto.Message)))

	n.Lock()

	if n.reqHandlers == nil {
		n.Unlock()
		return nil, errors.New("Client has already disconnected")
	}

	handler := n.reqHandlers[msgName]
	if msgName == "" || handler == nil {
		n.Unlock()
		return nil, errors.New("Invalid request type")
	}

	n.Unlock()

	message := request.(proto.Message)
	ctx, cancel := n.getReqContext(spanCtx, msgName)
	if cancel != nil {
		defer cancel()
	}

	jsonStr, err := protojson.Marshal(message)
	if err != nil {
		return nil, err
	}
	n.Logger().WithField("name", msgName).WithField("req", string(jsonStr)).Trace("sending request")

	defer func() {
		agentRPCDurationsHistogram.WithLabelValues(msgName).Observe(float64(time.Since(start).Nanoseconds() / int64(time.Millisecond)))
	}()
	return handler(ctx, request)
}

func (n *NodeAgent) getReqContext(ctx context.Context, reqName string) (newCtx context.Context, cancel context.CancelFunc) {
	newCtx = ctx
	switch reqName {
	case grpcWaitProcessRequest, grpcGetOOMEventRequest:
		// Wait and GetOOMEvent have no timeout
	case grpcCheckRequest:
		newCtx, cancel = context.WithTimeout(ctx, checkRequestTimeout)
	case grpcCreateContainerRequest:
		newCtx, cancel = context.WithTimeout(ctx, createContainerRequestTimeout)
	default:
		var requestTimeout = defaultRequestTimeout

		if timeout, ok := ctx.Value(customRequestTimeoutKey).(time.Duration); ok {
			requestTimeout = timeout
		}
		newCtx, cancel = context.WithTimeout(ctx, requestTimeout)
	}

	return newCtx, cancel
}

func (n *NodeAgent) Logger() *logrus.Entry {
	return virtLog.WithField("subsystem", "kata_agent")
}

func (n *NodeAgent) installReqFunc(c *AgentClient) {
	n.reqHandlers = make(map[string]reqFunc)
	n.reqHandlers[grpcCheckRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.HealthClient.Check(ctx, req.(*grpc.CheckRequest))
	}
	n.reqHandlers[grpcExecProcessRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.ExecProcess(ctx, req.(*grpc.ExecProcessRequest))
	}
	n.reqHandlers[grpcCreateSandboxRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.CreateSandbox(ctx, req.(*grpc.CreateSandboxRequest))
	}
	n.reqHandlers[grpcDestroySandboxRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.DestroySandbox(ctx, req.(*grpc.DestroySandboxRequest))
	}
	n.reqHandlers[grpcCreateContainerRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.CreateContainer(ctx, req.(*grpc.CreateContainerRequest))
	}
	n.reqHandlers[grpcStartContainerRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.StartContainer(ctx, req.(*grpc.StartContainerRequest))
	}
	n.reqHandlers[grpcRemoveContainerRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.RemoveContainer(ctx, req.(*grpc.RemoveContainerRequest))
	}
	n.reqHandlers[grpcSignalProcessRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.SignalProcess(ctx, req.(*grpc.SignalProcessRequest))
	}
	n.reqHandlers[grpcUpdateRoutesRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.UpdateRoutes(ctx, req.(*grpc.UpdateRoutesRequest))
	}
	n.reqHandlers[grpcUpdateInterfaceRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.UpdateInterface(ctx, req.(*grpc.UpdateInterfaceRequest))
	}
	n.reqHandlers[grpcUpdateEphemeralMountsRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.UpdateEphemeralMounts(ctx, req.(*grpc.UpdateEphemeralMountsRequest))
	}
	n.reqHandlers[grpcListInterfacesRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.ListInterfaces(ctx, req.(*grpc.ListInterfacesRequest))
	}
	n.reqHandlers[grpcListRoutesRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.ListRoutes(ctx, req.(*grpc.ListRoutesRequest))
	}
	n.reqHandlers[grpcAddARPNeighborsRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.AddARPNeighbors(ctx, req.(*grpc.AddARPNeighborsRequest))
	}
	n.reqHandlers[grpcOnlineCPUMemRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.OnlineCPUMem(ctx, req.(*grpc.OnlineCPUMemRequest))
	}
	n.reqHandlers[grpcUpdateContainerRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.UpdateContainer(ctx, req.(*grpc.UpdateContainerRequest))
	}
	n.reqHandlers[grpcWaitProcessRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.WaitProcess(ctx, req.(*grpc.WaitProcessRequest))
	}
	n.reqHandlers[grpcTtyWinResizeRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.TtyWinResize(ctx, req.(*grpc.TtyWinResizeRequest))
	}
	n.reqHandlers[grpcWriteStreamRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.WriteStdin(ctx, req.(*grpc.WriteStreamRequest))
	}
	n.reqHandlers[grpcCloseStdinRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.CloseStdin(ctx, req.(*grpc.CloseStdinRequest))
	}
	n.reqHandlers[grpcStatsContainerRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.StatsContainer(ctx, req.(*grpc.StatsContainerRequest))
	}
	n.reqHandlers[grpcPauseContainerRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.PauseContainer(ctx, req.(*grpc.PauseContainerRequest))
	}
	n.reqHandlers[grpcResumeContainerRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.ResumeContainer(ctx, req.(*grpc.ResumeContainerRequest))
	}
	n.reqHandlers[grpcReseedRandomDevRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.ReseedRandomDev(ctx, req.(*grpc.ReseedRandomDevRequest))
	}
	n.reqHandlers[grpcGuestDetailsRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.GetGuestDetails(ctx, req.(*grpc.GuestDetailsRequest))
	}
	n.reqHandlers[grpcMemHotplugByProbeRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.MemHotplugByProbe(ctx, req.(*grpc.MemHotplugByProbeRequest))
	}
	n.reqHandlers[grpcCopyFileRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.CopyFile(ctx, req.(*grpc.CopyFileRequest))
	}
	n.reqHandlers[grpcSetGuestDateTimeRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.SetGuestDateTime(ctx, req.(*grpc.SetGuestDateTimeRequest))
	}
	n.reqHandlers[grpcGetOOMEventRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.GetOOMEvent(ctx, req.(*grpc.GetOOMEventRequest))
	}
	n.reqHandlers[grpcGetMetricsRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.GetMetrics(ctx, req.(*grpc.GetMetricsRequest))
	}
	n.reqHandlers[grpcAddSwapRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.AddSwap(ctx, req.(*grpc.AddSwapRequest))
	}
	n.reqHandlers[grpcVolumeStatsRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.GetVolumeStats(ctx, req.(*grpc.VolumeStatsRequest))
	}
	n.reqHandlers[grpcResizeVolumeRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.ResizeVolume(ctx, req.(*grpc.ResizeVolumeRequest))
	}
	n.reqHandlers[grpcGetIPTablesRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.GetIPTables(ctx, req.(*grpc.GetIPTablesRequest))
	}
	n.reqHandlers[grpcSetIPTablesRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.SetIPTables(ctx, req.(*grpc.SetIPTablesRequest))
	}
	n.reqHandlers[grpcRemoveStaleVirtiofsShareMountsRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.RemoveStaleVirtiofsShareMounts(ctx, req.(*grpc.RemoveStaleVirtiofsShareMountsRequest))
	}
	n.reqHandlers[grpcSetPolicyRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return n.client.AgentServiceClient.SetPolicy(ctx, req.(*grpc.SetPolicyRequest))
	}
}
