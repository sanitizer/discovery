package discomodel

import (
	"fmt"
)

const (
	DISCOVERY_PACKAGE = 10 + iota
	DISCOVERY_REQUEST
)

const (
	CONNECTION_TYPE_UDP                       = "udp"
	DISCOVERY_PORT                            = "6666"
	BROADCAST_IP                              = "255.255.255.255"
	DEFAULT_LOCAL_BROADCAST_CONNECTION_STRING = ":0"
	DEFAULT_SEED_VALUE                        = "GMT"
)

type DiscoveryPkg struct {
	Type          int
	PkgValidation string
	AppServerIp   string
	AppServerPort string
	RequesterIp   string
	RequesterPort string
	Alias         string
}

func (this *DiscoveryPkg) String() string {
	return fmt.Sprintf("Type: %d\nPKG Validation: %q\nLocal Server Ip: %q\nServer Port: %q\nLocal Requester Ip: %q\nLocal Requester Port: %q\nAlias: %q",
		this.Type,
		this.PkgValidation,
		this.AppServerIp,
		this.AppServerPort,
		this.RequesterIp,
		this.RequesterPort,
		this.Alias)
}
