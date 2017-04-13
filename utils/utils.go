package utils

import (
	"errors"
	"net"
	"os"
	"strings"
	"time"
	// custom lib
	"github.com/rdegges/go-ipify"
)

const (
	DIAL_TIMEOUT = time.Second * 3
)

// concats host and port by ':' separator
func GetConnectionString(host string, port string) string {
	return strings.Join([]string{host, port}, ":")
}

// method will try to see if the connection is reachable
func ConnectionIsLive(conType string, ip string, port string) bool {
	connection, err := net.DialTimeout(conType, GetConnectionString(ip, port), DIAL_TIMEOUT)

	if err != nil {
		return false
	}

	defer connection.Close()
	return true
}

func GetLocalIpUsingLookup() (string, error) {
	host, _ := os.Hostname()
	addresses, _ := net.LookupIP(host)
	for _, address := range addresses {
		if ipv4 := address.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}
	return "", errors.New("Error finding local ip for the localhost using net.LookupIp")
}

func GetIpUsingIpify() (string, error) {
	return ipify.GetIp()
}
