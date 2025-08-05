package runc

import (
	"errors"
	"path/filepath"
	"time"
)

var kataAgentTracingTags = map[string]string{
	"source":    "runtime",
	"packafe":   "runc",
	"subsystem": "agent",
}

const (
	// KataEphemeralDevType creates a tmpfs backed volume for sharing files between containers.
	KataEphemeralDevType = "ephemeral"

	// KataLocalDevType creates a local directory inside the VM for sharing files between
	// containers.
	KataLocalDevType = "local"

	// Allocating an FSGroup that owns the pod's volumes
	fsGid = "fsgid"

	// path to vfio devices
	vfioPath = "/dev/vfio/"

	VirtualVolumePrefix = "io.katacontainers.volume="

	// enable debug console
	kernelParamDebugConsole           = "agent.debug_console"
	kernelParamDebugConsoleVPort      = "agent.debug_console_vport"
	kernelParamDebugConsoleVPortValue = "1026"

	// Default SELinux type applied to the container process inside guest
	defaultSeLinuxContainerType = "container_t"
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
	defaultEphemeralPath             = filepath.Join(defaultKataGuestSandboxDir, kataEphemeralDevType)
	grpcMaxDataSize                  = int64(1024 * 1024)
	localDirOptions                  = []string{"mode=0777"}
	maxHostnameLen                   = 64
	GuestDNSFile                     = "/etc/resolv.conf"
)

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

// KataAgentConfig is a structure storing information needed
// to reach the Kata Containers agent.
type KataAgentConfig struct {
	KernelModules      []string
	ContainerPipeSize  uint32
	DialTimeout        uint32
	CdhApiTimeout      uint32
	LongLiveConn       bool
	Debug              bool
	Trace              bool
	EnableDebugConsole bool
	Policy             string
}

// KataAgentState is the structure describing the data stored from this
// agent implementation.
type KataAgentState struct {
	URL string
}
