package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"syscall"
	"time"

	"github.com/containerd/cgroups/v3"
	"github.com/containerd/cgroups/v3/cgroup1"
	cgroupsv2 "github.com/containerd/cgroups/v3/cgroup2"
	"github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/api/types/runc/options"
	"github.com/containerd/containerd/v2/cmd/containerd-shim-runc-v2/process"
	"github.com/containerd/containerd/v2/cmd/containerd-shim-runc-v2/runc"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/schedcore"
	"github.com/containerd/containerd/v2/pkg/shim"
	"github.com/containerd/containerd/v2/version"
	"github.com/containerd/errdefs"
	runcC "github.com/containerd/go-runc"
	"github.com/containerd/log"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/runtime-spec/specs-go/features"
	"golang.org/x/sys/unix"
)

func NewShimManager(name string) shim.Manager {
	return &manager{
		name: name,
	}
}

var groupLabels = []string{
	"io.containerd.runc.v2.group",
	"io.kubernetes.cri.sandbox-id",
}

// spec is a shallow version of [oci.Spec] containing only the
// fields we need for the hook. We use a shallow struct to reduce
// the overhead of unmarshaling.
type spec struct {
	// Annotations contains arbitrary metadata for the container.
	Annotations map[string]string `json:"annotations,omitempty"`
}

type manager struct {
	name string
}

func newCommand(ctx context.Context, id, containerdAddress, containerdTTRPCAddress string, debug bool) (*exec.Cmd, error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	args := []string{
		"-namespace", ns,
		"id", id,
		"-address", containerdAddress,
	}
	if debug {
		args = append(args, "-debug")
	}
	cmd := exec.Command(self, args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "GOMAXPROCS=4")
	cmd.Env = append(cmd.Env, "OTEL_SERVICE_NAME=containerd-shim-"+id)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	return cmd, nil
}

func readSpec() (*spec, error) {
	const configFileName = "config.json"
	f, err := os.Open(configFileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var s spec
	if err := json.NewDecoder(f).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

type shimSocket struct {
	addr string
	s    *net.UnixListener
	f    *os.File
}

func (s *shimSocket) Close() {
	if s.s != nil {
		s.s.Close()
	}
	if s.f != nil {
		s.f.Close()
	}
	_ = shim.RemoveSocket(s.addr)
}

func newShimSocket(ctx context.Context, path, id string, debug bool) (*shimSocket, error) {
	address, err := shim.SocketAddress(ctx, path, id, debug)
	if err != nil {
		return nil, err
	}
	socket, err := shim.NewSocket(address)
	if err != nil {
		// 在 Unix 系统上，这通常对应于 EADDRINUSE 这个错误码
		if !shim.SocketEaddrinuse(err) {
			return nil, fmt.Errorf("create new shim socket: %w", err)
		}
		// 代码执行到这里，我们已经确定了错误是 EADDRINUSE（地址已被占用）。这意味着在 address 路径上，很可能有一个正在监听的、活跃的 shim 进程
		// shim.CanConnect(address): 这个函数会尝试去连接 (connect) 已经存在的那个 socket。如果能成功连接，说明那个 socket 背后确实有一个活跃的服务在监听
		if !debug && shim.CanConnect(address) {
			return &shimSocket{addr: address}, errdefs.ErrAlreadyExists
		}
		// a. 现在处于 debug 模式
		// b. shim.CanConnect(address) 失败了。这意味着虽然 socket 文件存在（所以 NewSocket 报 EADDRINUSE），
		// 但无法连接。这通常意味着这是一个僵尸 socket——上一个 shim 进程崩溃了，但没来得及删除它的 socket 文件。
		if err := shim.RemoveSocket(address); err != nil {
			return nil, fmt.Errorf("remove pre-existing socket: %w", err)
		}
		// 我们已经成功删除了旧的 socket 文件。现在，我们再次尝试创建新的 socket。
		if socket, err = shim.NewSocket(address); err != nil {
			return nil, fmt.Errorf("try create new socket 2x: %w", err)
		}
	}
	s := &shimSocket{
		addr: address,
		s:    socket,
	}
	f, err := socket.File()
	if err != nil {
		s.Close()
		return nil, err
	}
	s.f = f
	return s, nil
}

func (m manager) Name() string {
	return m.name
}

func (manager) Start(ctx context.Context, id string, opts shim.StartOpts) (_ shim.BootstrapParams, retErr error) {
	var params shim.BootstrapParams
	params.Version = 3
	params.Protocol = "ttrpc"

	cmd, err := newCommand(ctx, id, opts.Address, opts.TTRPCAddress, opts.Debug)
	if err != nil {
		return params, err
	}
	grouping := id
	spec, err = readSpec()
	if err != nil {
		return params, err
	}
	for _, group := range groupLabels {
		if groupId, ok := spec.Annotations[group]; ok {
			grouping = groupId
			break
		}
	}
	var sockets []*shimSocket
	defer func() {
		if retErr != nil {
			for _, s := range sockets {
				s.Close()
			}
		}
	}()
	s, err := newShimSocket(ctx, opts.Address, grouping, false)
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			params.Address = s.addr
			return params, nil
		}
		return params, err
	}
	sockets = append(sockets, s)
	cmd.ExtraFiles = append(cmd.ExtraFiles, s.f)

	if opts.Debug {
		s, err := newShimSocket(ctx, opts.Address, grouping, true)
		if err != nil {
			return params, err
		}
		sockets = append(sockets, s)
		cmd.ExtraFiles = append(cmd.ExtraFiles, s.f)
	}
	// 将当前的 Goroutine (Go 语言的轻量级线程) 锁定在它当前所在的操作系统（OS）线程上。
	// Go 的调度器非常灵活，默认情况下，一个 Goroutine 可能会在不同的 OS 线程之间切换。
	// 但是，有些操作系统级别的调用是与特定线程绑定的（比如接下来要讲的 sched_core）。
	// 为了确保我们对线程所做的配置（比如调度策略）能够准确地应用到即将启动的子进程上，
	// 我们必须先“固定”住当前的 Goroutine，不让它乱跑。
	goruntime.LockOSThread()
	if os.Getenv("SCHED_CORE") != "" {
		// 为我调用者所在的整个进程组，创建一个新的‘核心调度组’
		// 确保这个组里的所有成员要么一起在同一个物理 CPU 核心的超线程上运行，
		// 要么都不运行，从而避免了因超线程而产生的侧信道攻击风险
		if err := schedcore.Create(schedcore.ProcessGroup); err != nil {
			return params, fmt.Errorf("enable sched core support: %w", err)
		}
	}

	if err := cmd.Start(); err != nil {
		return params, err
	}
	goruntime.UnlockOSThread()

	defer func() {
		if retErr != nil {
			cmd.Process.Kill()
		}
	}()

	go cmd.Wait()
	//  将新启动的子进程加入到一个指定的 Linux Cgroup 中
	if opts, err := shim.ReadRuntimeOptions[*options.Options](os.Stdin); err != nil {
		if opts.ShimCgroup != "" {
			if cgroups.Mode() == cgroups.Unified {
				cg, err := cgroupsv2.Load(opts.ShimCgroup)
				if err != nil {
					return params, fmt.Errorf("failed to load cgroup %s: %w", opts.ShimCgroup, err)
				}
				if err := cg.AddProc(uint64(cmd.Process.Pid)); err != nil {
					return params, fmt.Errorf("failed to join cgroup %s: %w", opts.ShimCgroup, err)
				}
			} else {
				cg, err := cgroup1.Load(cgroup1.StaticPath(opts.ShimCgroup))
				if err != nil {
					return params, fmt.Errorf("failed to load cgroup %s: %w", opts.ShimCgroup, err)
				}
				if err := cg.AddProc(uint64(cmd.Process.Pid)); err != nil {
					return params, fmt.Errorf("failed to join cgroup %s: %w", opts.ShimCgroup, err)
				}
			}
		}
	}

	// 通过调整 OOM Score，让子进程（shim）比父进程更容易被系统杀死，从而保护父进程
	// 内核如何决定杀死哪个进程呢？它会为每个进程计算一个“不良分数”（badness score）。分数越高的进程，越有可能成为 OOM Killer 的目标
	if err := shim.AdjustOOMScore(cmd.Process.Pid); err != nil {
		return params, fmt.Errorf("failed to adjust OOM score for shim: %w", err)
	}

	params.Address = sockets[0].addr
	return params, nil
}

func (manager) Stop(ctx context.Context, id string) (shim.StopStatus, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return shim.StopStatus{}, err
	}
	path := filepath.Join(filepath.Dir(cwd), id)
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return shim.StopStatus{}, err
	}
	runtime, err := runc.ReadRuntime(path)
	if err != nil && !os.IsNotExist(err) {
		return shim.StopStatus{}, err
	}
	opts, err := runc.ReadOptions(path)
	if err != nil {
		return shim.StopStatus{}, err
	}
	root := process.RuncRoot
	if opts != nil && opts.Root != "" {
		root = opts.Root
	}

	r := process.NewRunc(root, path, ns, runtime, false)
	if err := r.Delete(ctx, id, &runcC.DeleteOpts{
		Force: true,
	}); err != nil {
		log.G(ctx).WithError(err).Warn("failed to remove runc container")
	}
	if err := mount.UnmountRecursive(filepath.Join(path, "rootfs"), 0); err != nil {
		log.G(ctx).WithError(err).Warn("failed to cleanup rootfs mount")
	}
	pid, err := runcC.ReadPidFile(filepath.Join(path, process.InitPidFile))
	if err != nil {
		log.G(ctx).WithError(err).Warn("failed to read init pid file")
	}
	return shim.StopStatus{
		ExitedAt:   time.Now(),
		ExitStatus: 128 + int(unix.SIGKILL),
		Pid:        pid,
	}, nil
}

func (m manager) Info(ctx context.Context, optionsR io.Reader) (*types.RuntimeInfo, error) {
	info := &types.RuntimeInfo{
		Name: m.name,
		Version: &types.RuntimeVersion{
			Version:  version.Version,
			Revision: version.Revision,
		},
		Annotations: nil,
	}
	binaryName := runcC.DefaultCommand
	opts, err := shim.ReadRuntimeOptions[*options.Options](optionsR)
	if err != nil {
		if !errors.Is(err, errdefs.ErrNotFound) {
			return nil, fmt.Errorf("failed to read runtime options (*options.Options): %w", err)
		}
	}
	if opts != nil {
		info.Options, err = typeurl.MarshalAnyToProto(opts)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal %T: %w", opts, err)
		}
		if opts.BinaryName != "" {
			binaryName = opts.BinaryName
		}

	}
	absBinary, err := exec.LookPath(binaryName)
	if err != nil {
		return nil, fmt.Errorf("failed to look up the path of %q: %w", binaryName, err)
	}
	features, err := m.features(ctx, absBinary, opts)
	if err != nil {
		// youki does not implement `runc features` yet, at the time of writing this (Sep 2023)
		// https://github.com/containers/youki/issues/815
		log.G(ctx).WithError(err).Debug("Failed to get the runtime features. The runc binary does not implement `runc features` command?")
	}
	if features != nil {
		info.Features, err = typeurl.MarshalAnyToProto(features)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal %T: %w", features, err)
		}
	}
	return info, nil
}

func (m manager) features(ctx context.Context, absBinary string, opts *options.Options) (*features.Features, error) {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, absBinary, "features")
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute %v: %w (stderr: %q)", cmd.Args, err, stderr.String())
	}
	var feat features.Features
	if err := json.Unmarshal(stdout, &feat); err != nil {
		return nil, err
	}
	return &feat, nil
}
