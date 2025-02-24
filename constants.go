package vrrp

import (
	"time"
)

type VRRPVersion byte

const (
	VRRPv1 VRRPVersion = 1
	VRRPv2 VRRPVersion = 2
	VRRPv3 VRRPVersion = 3
)

func (v VRRPVersion) String() string {
	switch v {
	case VRRPv1:
		return "VRRPVersion1"
	case VRRPv2:
		return "VRRPVersion2"
	case VRRPv3:
		return "VRRPVersion3"
	default:
		return "unknown VRRP version"
	}
}

const (
	stateInit = iota
	stateMaster
	stateBackup
)

const (
	vrrpTTL              = 255
	vrrpIPProtocolNumber = 112
)

type event byte

const (
	eventShutdown event = iota
	eventStart
)

func (e event) String() string {
	switch e {
	case eventStart:
		return "START"
	case eventShutdown:
		return "SHUTDOWN"
	default:
		return "unknown event"
	}
}

const (
	packetQueueSize  = 1000
	eventChannelSize = 1
)

type transition int

func (t transition) String() string {
	switch t {
	case Master2Backup:
		return "master to backup"
	case Backup2Master:
		return "backup to master"
	case Init2Master:
		return "init to master"
	case Init2Backup:
		return "init to backup"
	case Backup2Init:
		return "backup to init"
	case Master2Init:
		return "master to init"
	default:
		return "unknown transition"
	}
}

const (
	Master2Backup transition = iota
	Backup2Master
	Init2Master
	Init2Backup
	Master2Init
	Backup2Init
)

var (
	defaultPreempt                    = false
	defaultPriority              byte = 100
	defaultAdvertisementInterval      = 1 * time.Second
)
