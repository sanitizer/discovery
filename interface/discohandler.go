package dminterface

import (
	"net"
)

type DiscoveryHandler interface {
	SendDataToConnection(connection net.Conn, data interface{}) error
	ReceiveDataFromConnection(connection net.Conn) error
}
