// Copyright (c) 2018 Intel Corporation
// Copyright (c) 2018 HyperHQ Inc.
// Copyright (c) 2021 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//
// Note that some variables are "var" to allow them to be modified
// by the tests.

package katautils

import (
	config "github.com/peernode/peernode/src/runtime/pkg/device/config"
	govmmQemu "github.com/peernode/peernode/src/runtime/pkg/govmm/qemu"
)

// name is the name of the runtime
var NAME = "kata-runtime"

// name of the project
const PROJECT = "Kata Containers"

// prefix used to denote non-standard CLI commands and options.
const PROJECTPREFIX = "kata"

// original URL for this project
const PROJECTURL = "https://github.com/kata-containers"

// Project URL's organisation name
const PROJECTORG = "kata-containers"

const DEFAULTROOTDIRECTORY = "/var/run/kata-containers"

// commit is the git commit the runtime is compiled from.
var COMMIT = "9cebbab29d644ccd41b6eb58eb4020025f053e65"

// version is the runtime version.
var VERSION = "3.18.0"

// Default config file used by stateless systems.
var DEFAULTRUNTIMECONFIGURATION = "/usr/share/defaults/kata-containers/configuration.toml"

// Alternate config file that takes precedence over
// defaultRuntimeConfiguration.
var DEFAULTSYSCONFRUNTIMECONFIGURATION = "/etc/kata-containers/configuration.toml"
var defaultHypervisorPath = "/usr/bin/qemu-system-x86_64"
var defaultJailerPath = "/usr/bin/jailer"
var defaultImagePath = "/usr/share/kata-containers/kata-containers.img"
var defaultKernelPath = "/usr/share/kata-containers/vmlinuz.container"
var defaultInitrdPath = "/usr/share/kata-containers/kata-containers-initrd.img"
var defaultRootfsType = "ext4"
var defaultFirmwarePath = ""
var defaultFirmwareVolumePath = ""
var defaultMachineAccelerators = ""
var defaultCPUFeatures = ""
var systemdUnitName = "kata-containers.target"

const defaultKernelParams = ""
const defaultMachineType = "q35"
const defaultQgsPort = 4050

const defaultVCPUCount uint32 = 1
const defaultMaxVCPUCount uint32 = 0
const defaultMemSize uint32 = 2048 // MiB
const defaultMemSlots uint32 = 10
const defaultHypervisorLoglevel uint32 = 1
const defaultMemOffset uint64 = 0 // MiB
const defaultVirtioMem bool = false
const defaultBridgesCount uint32 = 1
const defaultInterNetworkingModel = "tcfilter"
const defaultDisableBlockDeviceUse bool = false
const defaultBlockDeviceDriver = "virtio-scsi"
const defaultBlockDeviceAIO string = "io_uring"
const defaultBlockDeviceCacheSet bool = false
const defaultBlockDeviceCacheDirect bool = false
const defaultBlockDeviceCacheNoflush bool = false
const defaultEnableIOThreads bool = false
const defaultEnableMemPrealloc bool = false
const defaultEnableReclaimGuestFreedMemory bool = false
const defaultEnableHugePages bool = false
const defaultEnableIOMMU bool = false
const defaultEnableIOMMUPlatform bool = false
const defaultFileBackedMemRootDir string = ""
const defaultEnableDebug bool = false
const defaultExtraMonitorSocket govmmQemu.MonitorProtocol = ""
const defaultDisableNestingChecks bool = false
const defaultMsize9p uint32 = 8192
const defaultEntropySource = "/dev/urandom"
const defaultGuestHookPath string = ""
const defaultVirtioFSCacheMode = "never"
const defaultDisableImageNvdimm = false
const defaultVhostUserStorePath string = "/var/run/kata-containers/vhost-user/"
const defaultVhostUserDeviceReconnect = 0
const defaultRxRateLimiterMaxRate = uint64(0)
const defaultTxRateLimiterMaxRate = uint64(0)
const defaultConfidentialGuest = false
const defaultSevSnpGuest = false
const defaultGuestSwap = false
const defaultRootlessHypervisor = false
const defaultDisableSeccomp = false
const defaultDisableGuestSeLinux = true
const defaultVfioMode = "guest-kernel"
const defaultLegacySerial = false

var defaultSGXEPCSize = int64(0)

const defaultTemplatePath string = "/run/vc/vm/template"
const defaultVMCacheEndpoint string = "/var/run/kata-containers/cache.sock"

// Default config file used by stateless systems.
var defaultRuntimeConfiguration = "/usr/share/defaults/kata-containers/configuration.toml"

const defaultHotPlugVFIO = config.NoPort
const defaultColdPlugVFIO = config.NoPort

const defaultPCIeRootPort = 0
const defaultPCIeSwitchPort = 0

const defaultRemoteHypervisorSocket = "/run/peerpod/hypervisor.sock"
const defaultRemoteHypervisorTimeout = 600
