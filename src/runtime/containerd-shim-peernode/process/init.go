//go:build !windows

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package process

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	grpc "github.com/billionairiam/peernode/src/runtime/containerd-shim-peernode/protocols/agent"
	"github.com/containerd/console"
	"github.com/containerd/containerd/v2/core/mount"
	google_protobuf "github.com/containerd/containerd/v2/pkg/protobuf/types"
	"github.com/containerd/containerd/v2/pkg/stdio"
	"github.com/containerd/fifo"
	runc "github.com/containerd/go-runc"
	"github.com/containerd/log"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Init represents an initial process for a container
// 它比 execProcess 更复杂，因为它不仅要管理一个进程，
// 还要管理创建这个进程所需的所有上下文和环境，
// 包括文件系统、网络、安全选项以及与底层运行时的交互方式
type Init struct {
	// 等待组，用于等待所有与容器相关的后台 goroutine 结束（如 I/O 拷贝任务）
	// 确保在销毁容器时，所有相关的后台任务都已完全停止并清理干净
	wg        sync.WaitGroup
	initState initState

	// mu is used to ensure that `Start()` and `Exited()` calls return in
	// the right order when invoked in separate goroutines.
	// This is the case within the shim implementation as it makes use of
	// the reaper interface.
	mu sync.Mutex
	// 一个阻塞/通知 channel，在主进程退出时被关闭
	// 允许其他 goroutine 高效地等待容器退出，而无需轮询
	waitBlock chan struct{}
	// 容器的工作目录路径。这通常是 /var/lib/containerd/... 下的一个目录，用于存放一些持久化的工作文件
	WorkDir string
	// 容器的唯一 ID。这是整个容器的标识，而不仅仅是主进程的
	id string
	// OCI Bundle 的路径
	Bundle string
	// 如果容器需要一个伪终端 (TTY)，这个字段会持有该终端对象
	// 用于创建交互式容器（如 docker run -it）
	console console.Console
	// 一个平台相关的 I/O 处理器
	// 用于处理一些平台特有的 I/O 操作，例如在 Windows 和 Linux 上创建管道的方式可能不同。
	Platform stdio.Platform
	// I/O 的原始配置蓝图
	// 保存用户关于 I/O 的原始请求，例如是否需要终端，日志驱动程序的 URI 等
	io *processIO
	// 一个指向 runc 运行时实例的指针
	// 封装了与 runc 二进制文件交互的所有命令（如 runc run, runc state, runc kill 等）。
	// 所有对容器的生命周期操作（创建、杀死、暂停）最终都会通过这个对象来执行。
	runtime *runc.Runc
	agent   *NodeAgent
	// agent   *task.NodeAgent
	// pausing preserves the pausing state.
	// 一个原子布尔值，表示容器当前是否正处于“暂停中”或“恢复中”的过渡状态
	// pause 和 resume 操作不是瞬时完成的。使用原子变量可以无锁地、安全地检查这个状态，防止在暂停过程中执行其他冲突的操作。
	pausing atomic.Bool
	// 主进程的退出状态码。
	status int
	exited time.Time
	// 主进程在宿主机上的 PID
	pid int
	// 一个存放所有需要关闭的资源的切片。
	// 统一管理容器生命周期中创建的所有可关闭资源（文件、管道、网络连接等），
	// 确保在容器销毁时能一并关闭，防止资源泄露。
	closers []io.Closer
	// 一个专门用来关闭主进程标准输入流的 Closer
	// 用于通知主进程输入已经结束
	stdin  io.Closer
	stdio  stdio.Stdio
	Rootfs string
	// 用于设置 I/O 相关文件（如命名管道）的所有者的用户 ID 和组 ID
	IoUID int
	IoGID int
	// 告诉 runc 不要使用 pivot_root 系统调用来切换根文件系统
	// pivot_root 是标准的切换 rootfs 的方式，但在某些特殊环境（如某些无系统调用的容器环境）下可能无法使用。这提供了一个备用方案
	NoPivotRoot bool
	// 告诉 runc 不要为容器创建新的内核密钥环
	// 在某些安全策略非常严格的系统上，创建新密钥环可能会被禁止。这个选项允许在这些环境下也能运行容器。
	NoNewKeyring bool
	// 如果使用 CRIU (Checkpoint/Restore In Userspace) 技术，这个字段指定了存放容器状态快照（检查点）的工作目录
	// CRIU 可以将一个正在运行的容器的完整内存状态“冻结”并保存到磁盘，之后可以从这个快照中“解冻”并恢复容器。这对于容器的热迁移非常关键
	CriuWorkPath string
}

// NewRunc returns a new runc instance for a process
func NewRunc(root, path, namespace, runtime string, systemd bool) *runc.Runc {
	if root == "" {
		root = RuncRoot
	}
	return &runc.Runc{
		Command:       runtime,
		Log:           filepath.Join(path, "log.json"),
		LogFormat:     runc.JSON,
		PdeathSignal:  unix.SIGKILL,
		Root:          filepath.Join(root, namespace),
		SystemdCgroup: systemd,
	}
}

// New returns a new process
func New(id string, runtime *runc.Runc, stdio stdio.Stdio) *Init {
	p := &Init{
		id:        id,
		runtime:   runtime,
		stdio:     stdio,
		status:    0,
		waitBlock: make(chan struct{}),
	}
	p.initState = &createdState{p: p}
	return p
}

// Create the process with the provided config
func (p *Init) Create(ctx context.Context, r *CreateConfig) (retError error) {
	var (
		err     error
		socket  *runc.Socket
		pio     *processIO
		pidFile = newPidFile(p.Bundle)
	)

	if r.Terminal {
		if socket, err = runc.NewTempConsoleSocket(); err != nil {
			return fmt.Errorf("failed to create OCI runtime console socket: %w", err)
		}
		defer socket.Close()
	} else {
		if pio, err = createIO(ctx, p.id, p.IoUID, p.IoGID, p.stdio); err != nil {
			return fmt.Errorf("failed to create init process I/O: %w", err)
		}
		p.io = pio
		defer func() {
			if retError != nil && p.io != nil {
				p.io.Close()
			}
		}()
	}
	if r.Checkpoint != "" {
		return p.createCheckpointedState(r, pidFile)
	}
	req := &grpc.CreateContainerRequest{
		PidFile:      pidFile.Path(),
		NoPivot:      p.NoPivotRoot,
		NoNewKeyring: p.NoNewKeyring,
	}

	if _, err = p.agent.sendReq(ctx, req); err != nil {
		if err.Error() == context.DeadlineExceeded.Error() {
			return status.Errorf(codes.DeadlineExceeded, "CreateContainerRequest timed out")
		}
		return err
	}

	// opts := &runc.CreateOpts{
	// 	PidFile:      pidFile.Path(),
	// 	NoPivot:      p.NoPivotRoot,
	// 	NoNewKeyring: p.NoNewKeyring,
	// }
	// if p.io != nil {
	// 	opts.IO = p.io.IO()
	// }
	// if socket != nil {
	// 	opts.ConsoleSocket = socket
	// }

	// if err := p.runtime.Create(ctx, r.ID, r.Bundle, opts); err != nil {
	// 	return p.runtimeError(err, "OCI runtime create failed")
	// }
	if r.Stdin != "" {
		if err := p.openStdin(r.Stdin); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if socket != nil {
		console, err := socket.ReceiveMaster()
		if err != nil {
			return fmt.Errorf("failed to retrieve console master: %w", err)
		}
		console, err = p.Platform.CopyConsole(ctx, console, p.id, r.Stdin, r.Stdout, r.Stderr, &p.wg)
		if err != nil {
			return fmt.Errorf("failed to start console copy: %w", err)
		}
		p.console = console
	} else {
		if err := pio.Copy(ctx, &p.wg); err != nil {
			return fmt.Errorf("failed to start io pipe copy: %w", err)
		}
	}
	pid, err := pidFile.Read()
	if err != nil {
		return fmt.Errorf("failed to retrieve OCI runtime container pid: %w", err)
	}
	p.pid = pid
	return nil
}

func (p *Init) openStdin(path string) error {
	sc, err := fifo.OpenFifo(context.Background(), path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("failed to open stdin fifo %s: %w", path, err)
	}
	p.stdin = sc
	p.closers = append(p.closers, sc)
	return nil
}

// CRIU (Checkpoint/Restore In Userspace)。这是一个 Linux 工具，可以“冻结”一个正在运行的应用程序
// （或一组程序，如一个容器），将其完整的内存、进程状态、文件描述符等保存到磁盘上（这就是一个检查点），
// 然后在未来的某个时间点，从这些文件中将应用程序完全恢复到它被冻结时的状态，甚至可以在另一台机器上恢复。
func (p *Init) createCheckpointedState(r *CreateConfig, pidFile *pidFile) error {
	opts := &runc.RestoreOpts{
		CheckpointOpts: runc.CheckpointOpts{
			ImagePath:  r.Checkpoint,
			WorkDir:    p.CriuWorkPath,
			ParentPath: r.ParentCheckpoint,
		},
		PidFile:     pidFile.Path(),
		NoPivot:     p.NoPivotRoot,
		Detach:      true,
		NoSubreaper: true,
	}

	if p.io != nil {
		opts.IO = p.io.IO()
	}

	p.initState = &createdCheckpointState{
		p:    p,
		opts: opts,
	}
	return nil
}

// Wait for the process to exit
func (p *Init) Wait(ctx context.Context) error {
	select {
	case <-p.waitBlock:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ID of the process
func (p *Init) ID() string {
	return p.id
}

// Pid of the process
func (p *Init) Pid() int {
	return p.pid
}

// ExitStatus of the process
func (p *Init) ExitStatus() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.status
}

// ExitedAt at time when the process exited
func (p *Init) ExitedAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.exited
}

// Status of the process
func (p *Init) Status(ctx context.Context) (string, error) {
	if p.pausing.Load() {
		return "pausing", nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Status(ctx)
}

// Start the init process
func (p *Init) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Start(ctx)
}

func (p *Init) start(ctx context.Context) error {
	err := p.runtime.Start(ctx, p.id)
	return p.runtimeError(err, "OCI runtime start failed")
}

// SetExited of the init process with the next status
func (p *Init) SetExited(status int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.initState.SetExited(status)
}

func (p *Init) setExited(status int) {
	p.exited = time.Now()
	p.status = status
	p.Platform.ShutdownConsole(context.Background(), p.console)
	close(p.waitBlock)
}

// Delete the init process
func (p *Init) Delete(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Delete(ctx)
}

func (p *Init) delete(ctx context.Context) error {
	waitTimeout(ctx, &p.wg, 2*time.Second)
	err := p.runtime.Delete(ctx, p.id, nil)
	// ignore errors if a runtime has already deleted the process
	// but we still hold metadata and pipes
	//
	// this is common during a checkpoint, runc will delete the container state
	// after a checkpoint and the container will no longer exist within runc
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			err = nil
		} else {
			err = p.runtimeError(err, "failed to delete task")
		}
	}
	if p.io != nil {
		for _, c := range p.closers {
			c.Close()
		}
		p.io.Close()
	}
	if err2 := mount.UnmountRecursive(p.Rootfs, 0); err2 != nil {
		log.G(ctx).WithError(err2).Warn("failed to cleanup rootfs mount")
		if err == nil {
			err = fmt.Errorf("failed rootfs umount: %w", err2)
		}
	}
	return err
}

// Resize the init processes console
func (p *Init) Resize(ws console.WinSize) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.console == nil {
		return nil
	}
	return p.console.Resize(ws)
}

// Pause the init process and all its child processes
func (p *Init) Pause(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Pause(ctx)
}

// Resume the init process and all its child processes
func (p *Init) Resume(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Resume(ctx)
}

// Kill the init process
func (p *Init) Kill(ctx context.Context, signal uint32, all bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Kill(ctx, signal, all)
}

func (p *Init) kill(ctx context.Context, signal uint32, all bool) error {
	err := p.runtime.Kill(ctx, p.id, int(signal), &runc.KillOpts{
		All: all,
	})
	return checkKillError(err)
}

// KillAll processes belonging to the init process
func (p *Init) KillAll(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	err := p.runtime.Kill(ctx, p.id, int(unix.SIGKILL), &runc.KillOpts{
		All: true,
	})
	return p.runtimeError(err, "OCI runtime killall failed")
}

// Stdin of the process
func (p *Init) Stdin() io.Closer {
	return p.stdin
}

// Runtime returns the OCI runtime configured for the init process
func (p *Init) Runtime() *runc.Runc {
	return p.runtime
}

// Exec returns a new child process
func (p *Init) Exec(ctx context.Context, path string, r *ExecConfig) (Process, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Exec(ctx, path, r)
}

// exec returns a new exec'd process
func (p *Init) exec(ctx context.Context, path string, r *ExecConfig) (Process, error) {
	// process exec request
	var spec specs.Process
	if err := json.Unmarshal(r.Spec.Value, &spec); err != nil {
		return nil, err
	}
	spec.Terminal = r.Terminal

	e := &execProcess{
		id:     r.ID,
		path:   path,
		parent: p,
		spec:   spec,
		stdio: stdio.Stdio{
			Stdin:    r.Stdin,
			Stdout:   r.Stdout,
			Stderr:   r.Stderr,
			Terminal: r.Terminal,
		},
		waitBlock: make(chan struct{}),
	}
	e.execState = &execCreatedState{p: e}
	return e, nil
}

// Checkpoint the init process
func (p *Init) Checkpoint(ctx context.Context, r *CheckpointConfig) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Checkpoint(ctx, r)
}

func (p *Init) checkpoint(ctx context.Context, r *CheckpointConfig) error {
	var actions []runc.CheckpointAction
	if !r.Exit {
		actions = append(actions, runc.LeaveRunning)
	}
	// keep criu work directory if criu work dir is set
	work := r.WorkDir
	if work == "" {
		work = filepath.Join(p.WorkDir, "criu-work")
		defer os.RemoveAll(work)
	}
	if err := p.runtime.Checkpoint(ctx, p.id, &runc.CheckpointOpts{
		WorkDir:                  work,
		ImagePath:                r.Path,
		AllowOpenTCP:             r.AllowOpenTCP,
		AllowExternalUnixSockets: r.AllowExternalUnixSockets,
		AllowTerminal:            r.AllowTerminal,
		FileLocks:                r.FileLocks,
		EmptyNamespaces:          r.EmptyNamespaces,
	}, actions...); err != nil {
		dumpLog := filepath.Join(p.Bundle, "criu-dump.log")
		if cerr := copyFile(dumpLog, filepath.Join(work, "dump.log")); cerr != nil {
			log.G(ctx).WithError(cerr).Error("failed to copy dump.log to criu-dump.log")
		}
		return fmt.Errorf("%s path= %s", criuError(err), dumpLog)
	}
	return nil
}

// Update the processes resource configuration
func (p *Init) Update(ctx context.Context, r *google_protobuf.Any) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Update(ctx, r)
}

func (p *Init) update(ctx context.Context, r *google_protobuf.Any) error {
	var resources specs.LinuxResources
	if err := json.Unmarshal(r.Value, &resources); err != nil {
		return err
	}
	return p.runtime.Update(ctx, p.id, &resources)
}

// Stdio of the process
func (p *Init) Stdio() stdio.Stdio {
	return p.stdio
}

func (p *Init) runtimeError(rErr error, msg string) error {
	if rErr == nil {
		return nil
	}

	rMsg, err := getLastRuntimeError(p.runtime)
	switch {
	case err != nil:
		return fmt.Errorf("%s: %s (%s): %w", msg, "unable to retrieve OCI runtime error", err.Error(), rErr)
	case rMsg == "":
		return fmt.Errorf("%s: %w", msg, rErr)
	default:
		return fmt.Errorf("%s: %s", msg, rMsg)
	}
}

func withConditionalIO(c stdio.Stdio) runc.IOOpt {
	return func(o *runc.IOOption) {
		o.OpenStdin = c.Stdin != ""
		o.OpenStdout = c.Stdout != ""
		o.OpenStderr = c.Stderr != ""
	}
}
