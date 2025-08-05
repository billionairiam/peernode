package process

import (
	google_protobuf "github.com/containerd/containerd/v2/pkg/protobuf/types"
)

type Mount struct {
	Type    string
	Source  string
	Target  string
	Options []string
}

// CreateConfig hold task creation configuration
type CreateConfig struct {
	ID               string
	Bundle           string
	Runtime          string
	Rootfs           []Mount
	Terminal         bool
	Stdin            string
	Stdout           string
	Stderr           string
	Checkpoint       string
	ParentCheckpoint string
	Options          *google_protobuf.Any
}

// ExecConfig holds exec creation configuration
type ExecConfig struct {
	ID       string
	Terminal bool
	Stdin    string
	Stdout   string
	Stderr   string
	Spec     *google_protobuf.Any
}

// CheckpointConfig holds task checkpoint configuration
type CheckpointConfig struct {
	WorkDir string
	Path    string
	Exit    bool
	// 含义: 允许处理已建立的 TCP 连接（Allow Open TCP Connections）。
	// 作用: 默认情况下，CRIU 对处理活跃的 TCP 连接非常谨慎，因为它无法完美地恢复一个跨机器的 TCP 连接状态。
	// 如果设置为 true，你是在告诉 CRIU：“我知道风险，请尝试保存并恢复所有已建立的 TCP 连接状态”。这需要内核的特定功能（TCP_REPAIR）支持。
	// 警告: 这是一个高级且有风险的选项。恢复后的 TCP 连接可能会出问题，除非网络环境经过特殊配置。
	AllowOpenTCP bool
	// 含义: 允许处理外部 Unix Socket 连接（Allow External Unix Sockets）。
	// 作用: Unix Domain Socket 通常用于同一台机器上的进程间通信。
	// 如果一个容器的进程连接到了容器外部的 Unix Socket，CRIU 默认会拒绝检查点，
	// 因为它无法保证恢复后那个外部 Socket 还存在或有效。
	// 设置为 true 表示允许 CRIU 检查点这样的容器，但风险自负。
	AllowExternalUnixSockets bool
	// 含义: 允许处理终端会话（Allow Terminal Session）。
	// 作用: 如果容器附加到了一个 TTY（伪终端），
	// 例如你通过 docker exec -it 进入了容器，
	// CRIU 默认可能无法处理这种情况。
	// 将此项设置为 true 允许 CRIU 尝试对连接到终端的进程进行检查点。
	AllowTerminal   bool
	FileLocks       bool
	EmptyNamespaces []string
}
