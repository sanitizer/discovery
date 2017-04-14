package discovery

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"
	// gitlab apis
	"github.com/sanitizer/discovery/interface"
	"github.com/sanitizer/discovery/model"
	"github.com/sanitizer/discovery/security"
	"github.com/sanitizer/discovery/utils"
)

const (
	DEFAULT_TIMEOUT = time.Second * 30
)

/*
	expect discovery ip and port to be set
	other attrs are optional
	default timeout 30 sec
	if stop server chan is not set
	server will operate in infinite loop mode
*/
type DiscoveryAgent struct {
	DiscoveryServerPort string
	StopDiscoveryServer <-chan int // only receiving channel
	ServerTimeout       time.Duration
}

func (this *DiscoveryAgent) String() string {
	return fmt.Sprintf("Discovery Server Port: %q\nServer timeout: %q\n",
		this.DiscoveryServerPort,
		this.ServerTimeout)
}

// check if discovery port was set. If not than we will set it to the default port
// defined in discomodel
func (this *DiscoveryAgent) handleMissingDiscoveryServerPort() {
	if this.DiscoveryServerPort == "" {
		this.DiscoveryServerPort = discomodel.DISCOVERY_PORT
	}
}

// infinite loop of accepting messages on udpconnection
func handleInfiniteServerLoop(udpConnection net.Conn, dataManager dminterface.DiscoveryHandler) {
	for {
		waitForDiscoMessage(udpConnection, dataManager)
	}
}

// udpConnection - net.Conn with connection type UDP
// dataManager - implementation of interface DiscoveryHandler
func waitForDiscoMessage(udpConnection net.Conn,
			 dataManager dminterface.DiscoveryHandler) {

	//TODO i need some way to allow user to define what type of model they want to use
	dataManager.ReceiveDataFromConnection(udpConnection)
}

// creating udp connection for discovery server
func (this *DiscoveryAgent) GetServerUdpConnection() (net.Conn, error) {
	this.handleMissingDiscoveryServerPort()

	// binding to port :PORT instead of IP:PORT, as has issues when trying to get broadcast message
	serverIp, e2 := net.ResolveUDPAddr(discomodel.CONNECTION_TYPE_UDP, utils.GetConnectionString("", this.DiscoveryServerPort))
	if e2 != nil {
		return nil, errors.New("Resolve Udp Connection for Discovery Server error: " + e2.Error())
	}

	return net.ListenUDP(discomodel.CONNECTION_TYPE_UDP, serverIp)
}

//this function will build your a default encrypted package using DiscoveryPkg model
func (this *DiscoveryAgent) BuildEncryptedDefaultDiscoveryRequest(discoServerIp string) (discomodel.DiscoveryPkg, error) {
	this.handleMissingDiscoveryServerPort()

	s := new(security.Security)
	token, err1 := s.GenerateDiscoReqToken()
	encrPkgValidation, err2 := s.EncryptCFB([]byte(token))
	encrLocalRequesterIp, err3 := s.EncryptCFB([]byte(discoServerIp))
	encrLocalRequesterPort, err4 := s.EncryptCFB([]byte(this.DiscoveryServerPort))

	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		var strBldr bytes.Buffer
		strBldr.WriteString("Error while encrypting Discovery Request:\n")

		if err1 != nil {
			strBldr.WriteString("\tToken Generate error: " + err1.Error() + "\n")
		}

		if err2 != nil {
			strBldr.WriteString("\tPackage validation error: " + err2.Error() + "\n")
		}

		if err3 != nil {
			strBldr.WriteString("\tPublic Requester Ip error: " + err3.Error() + "\n")
		}

		if err4 != nil {
			strBldr.WriteString("\tPublic Requester Port error: " + err4.Error() + "\n")
		}

		return discomodel.DiscoveryPkg{}, errors.New(strBldr.String())
	}

	return discomodel.DiscoveryPkg{Type: discomodel.DISCOVERY_REQUEST,
			PkgValidation: s.HideLengthInCFBEncryptedString(encrPkgValidation,
				len(token)),
			RequesterIp: s.HideLengthInCFBEncryptedString(encrLocalRequesterIp,
				len(discoServerIp)),
			RequesterPort: s.HideLengthInCFBEncryptedString(encrLocalRequesterPort,
				len(this.DiscoveryServerPort))},
		nil
}

/*
 starts listening on udp server connection for udp messages
 after the server is done, function will close udp connection listener
 expected data type is discomodel.DiscoveryPkg
 dataManager - implementation of interface DiscoveryHandler
*/
func (this *DiscoveryAgent) StartDiscoveryServer(dataManager dminterface.DiscoveryHandler) {
	udpConnection, e := this.GetServerUdpConnection()
	if e != nil {
		fmt.Printf("Error creating discovery server udp connection: %q", e.Error())
		return
	}

	defer udpConnection.Close()

	if this.StopDiscoveryServer == nil {
		handleInfiniteServerLoop(udpConnection, dataManager)
	} else {
		if this.ServerTimeout == 0 {
			this.ServerTimeout = DEFAULT_TIMEOUT
		}

		fmt.Printf("Discovery Server timeouts will happen every %q\n", this.ServerTimeout)

	LOOP:
		for {
			select {
			case <-this.StopDiscoveryServer:
				fmt.Println("Stopping Discovery server...")
				break LOOP
			default:
				// setting timeout to allow checks on the channel
				udpConnection.SetDeadline(time.Now().Add(this.ServerTimeout))
				waitForDiscoMessage(udpConnection, dataManager)
			}
		}
	}

	fmt.Println("Discovery server was stopped")
}

/*
 function creates udp connection using discovery ip
 sends default discovery request message to the discovery ip
 the discovery request only being sent on local network
 after send is done, udp connection will close
 dataManager - implementation of interface DiscoveryHandler
 data - discomodel.DiscoveryPkg
*/
func (this DiscoveryAgent) BroadcastDiscoveryMessage(dataManager dminterface.DiscoveryHandler, data interface{}, targetServerPort string) error {
	ServerAddr, e1 := net.ResolveUDPAddr(discomodel.CONNECTION_TYPE_UDP,
		utils.GetConnectionString(discomodel.BROADCAST_IP, targetServerPort))

	if e1 != nil {
		return errors.New("Error resolving broadcast address" + e1.Error())
	}

	LocalAddr, e2 := net.ResolveUDPAddr(discomodel.CONNECTION_TYPE_UDP,
		discomodel.DEFAULT_LOCAL_BROADCAST_CONNECTION_STRING)

	if e2 != nil {
		return errors.New("Error resolving local udp addr" + e2.Error())
	}

	DiscoveryAgent, e3 := net.DialUDP(discomodel.CONNECTION_TYPE_UDP,
		LocalAddr,
		ServerAddr)

	if e3 != nil {
		return errors.New("Error connection to the broadcast connection" + e3.Error())
	}

	defer DiscoveryAgent.Close()

	return dataManager.SendDataToConnection(DiscoveryAgent, data)
}
