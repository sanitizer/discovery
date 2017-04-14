package dmimpl

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	// gitlab apis
	"github.com/sanitizer/discovery/security"
	"github.com/sanitizer/discovery/utils"
	"github.com/sanitizer/discovery/model"
)

type DefaultDiscoveryHandler struct{
	AppIp               string
	AppPort             string
	DiscoveredTargets   chan discomodel.DiscoveredTarget
}

func (this *DefaultDiscoveryHandler) String() string {
	return fmt.Sprintf("App Server Ip: %q\nApp Server Port: %q\n",
		this.AppIp,
		this.AppPort)
}

// check if discovery port was set
func (this *DefaultDiscoveryHandler) handleMissingAppPort() error {
	if this.AppPort == "" {
		return errors.New("Error: App Port was not set on Discovery Manager struct.")
	}
	return nil
}

// check if discovery port was set
func (this *DefaultDiscoveryHandler) handleMissingAppIp() error {
	if this.AppIp == "" {
		return errors.New("Error: App Ip was not set on Discovery Manager struct.")
	}
	return nil
}

func (this DefaultDiscoveryHandler) SendDataToConnection(connection net.Conn, data interface{}) error {
	// Will write to network.
	enc := gob.NewEncoder(connection)
	return enc.Encode(data)
}

// receive data from connection using gob
func (this DefaultDiscoveryHandler) ReceiveDataFromConnection(connection net.Conn) error {
	newInstance := new(discomodel.DiscoveryPkg)
	// Will read from buffer
	decoder := gob.NewDecoder(connection)
	// Decode (receive) the value.
	e := decoder.Decode(newInstance)
	if e != nil && !strings.Contains(e.Error(), "timeout") {
		fmt.Println("Error receiving discovery data. " + e.Error())
		return e
	} else if e != nil {
		fmt.Println("Planned server timeout: " + e.Error())
		return e
	} else {
		go this.handleDiscoveryData(newInstance)
	}
	return nil
}

// checks for all required attrs to be set on DiscoveryAgent Struct
func (this *DefaultDiscoveryHandler) handleDiscoveryHandlerStruct() error {
	e1 := this.handleMissingAppIp()
	e2 := this.handleMissingAppPort()
	if e1 != nil || e2 != nil {
		var strBldr bytes.Buffer
		strBldr.WriteString("Error while checking Discovery Agent struct:\n")

		if e1 != nil {
			strBldr.WriteString("\tApp ip was not set: " + e1.Error() + "\n")
		}

		if e2 != nil {
			strBldr.WriteString("\tApp port was not set: " + e2.Error() + "\n")
		}

		return errors.New(strBldr.String())
	}
	return nil
}

// logic around handling data received from udpconnection
func (this DefaultDiscoveryHandler) handleDiscoveryData(instance *discomodel.DiscoveryPkg) {
	if instance != nil {
		e1 := this.handleDiscoveryRequest(instance)

		if e1 != nil {
			fmt.Println("Error handling discovery data. " + e1.Error())
		}
	}
}

// this method will decrypt data that was received from connection
// the method relies on DiscoveryPkg model
func decryptDiscoveryPkg(data *discomodel.DiscoveryPkg) error {
	/*
		the reason to do all the below operations is that the length of
		original data inserted into the encrypted data
	*/
	s := new(security.Security)
	decrSerPort, e1 := decryptCFBString(data.AppServerPort, s)
	decrLocAppServerIp, e2 := decryptCFBString(data.AppServerIp, s)
	decrPkgVal, e3 := decryptCFBString(data.PkgValidation, s)
	decrLocReqIp, e4 := decryptCFBString(data.RequesterIp, s)
	decrLocReqPort, e5 := decryptCFBString(data.RequesterPort, s)
	decrAlias, e6 := decryptCFBString(data.Alias, s)

	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil {
		var strBldr bytes.Buffer
		strBldr.WriteString("Error while decrypting Discovery Data:\n")

		if e1 != nil {
			strBldr.WriteString("\tServer Port error: " + e1.Error() + "\n")
		}

		if e2 != nil {
			strBldr.WriteString("\nLocal Server Ip error: " + e2.Error() + "\n")
		}

		if e3 != nil {
			strBldr.WriteString("\tPackage validation error: " + e3.Error() + "\n")
		}

		if e4 != nil {
			strBldr.WriteString("\tLocal Requester Ip error: " + e4.Error() + "\n")
		}

		if e5 != nil {
			strBldr.WriteString("\tLocal Requester Port error: " + e5.Error() + "\n")
		}

		if e6 != nil {
			strBldr.WriteString("\tAlias error: " + e6.Error() + "\n")
		}

		return errors.New(strBldr.String())
	}

	//setting decrypted values to the passed data
	data.PkgValidation = decrPkgVal
	data.AppServerIp = decrLocAppServerIp
	data.AppServerPort = decrSerPort
	data.RequesterIp = decrLocReqIp
	data.RequesterPort = decrLocReqPort
	data.Alias = decrAlias

	return nil
}

/*
 logic around handling received package from connection
 check if this is the discovery msg
 check what type of discovery msg it is
 check if the discovery request is a loopback
 if all checks passed, send discovery response
*/
func (this DefaultDiscoveryHandler) handleDiscoveryRequest(receivedData *discomodel.DiscoveryPkg) error {

	decrErr := decryptDiscoveryPkg(receivedData)

	if decrErr != nil {
		return decrErr
	}

	s := new(security.Security)

	expectedToken, err := s.GenerateDiscoReqToken()
	if err != nil {
		return err
	}

	appIpErr := this.handleMissingAppIp()
	if appIpErr != nil {
		return appIpErr
	}


	//checking if we got a discovery request with correct validation string, making sure we are not processing the discovery
	//package from your own discovery agent, checking if the package is of type discovery request
	if receivedData.Type == discomodel.DISCOVERY_REQUEST && receivedData.PkgValidation == expectedToken {
		fmt.Println("Received Discovery Request")
		if receivedData.RequesterIp != this.AppIp {
			fmt.Println("DiscoveryPkg message was validated")
			return this.handleDiscoveryResponse(receivedData)
		} else {
			fmt.Println("DiscoveryPkg message was dropped as a loopback discovery msg")
		}
	} else if receivedData.Type == discomodel.DISCOVERY_PACKAGE && receivedData.PkgValidation == expectedToken {
		fmt.Println("Received Discovery Package")
		port, portError := strconv.Atoi(receivedData.AppServerPort)

		if portError != nil {
			fmt.Println("Dropped Discovery Package")
			return errors.New("Error parsing port into int: " + portError.Error())
		}

		if (this.DiscoveredTargets != nil) {
			this.DiscoveredTargets <- discomodel.DiscoveredTarget{Ip: receivedData.AppServerIp, Port: port, Alias: receivedData.Alias}
		}
	} else {
		fmt.Println("DiscoveryPkg message was not validated or not recognized")
	}

	return nil
}

// send discovery response using discovery pkg model
// data sent back is server ip, server port, hostname as alias for the discovered system
func (this DefaultDiscoveryHandler) handleDiscoveryResponse(receivedData *discomodel.DiscoveryPkg) error {
	e := this.handleDiscoveryHandlerStruct()

	if e != nil {
		return e
	}

	discoveryResponse, e1 := this.BuildDefaultEncryptedDiscoveryResponse(this.AppIp, this.AppPort)

	if e1 != nil {
		return errors.New("Error building default encrypted discovery response. " + e1.Error())
	}

	ResponceConnection, e2 := this.GetResponseUdpConnection(receivedData.RequesterIp, receivedData.RequesterPort)

	if e2 != nil {
		return errors.New("Error building a default response udp connection. " + e2.Error())
	}

	defer ResponceConnection.Close()

	e3 := this.SendDataToConnection(ResponceConnection, discoveryResponse)

	if e3 != nil {
		return errors.New("Error sending discovery response data" + e3.Error())
	}

	fmt.Println("Sent discovery data to requester : " + receivedData.RequesterIp + ":" + receivedData.RequesterPort)
	return nil
}

/*
 this method builds a default response for discovery request and relies on DiscoveryPkg model
 setting validation string, server ip, server port, alias(hostname)
 using cfb encrytion for all the data
*/
func (this DefaultDiscoveryHandler) BuildDefaultEncryptedDiscoveryResponse(appIp string, appPort string) (discomodel.DiscoveryPkg, error) {

	s := new(security.Security)
	AppServerIp, err1 := s.EncryptCFB([]byte(appIp))
	port, err2 := s.EncryptCFB([]byte(appPort))
	token, err3 := s.GenerateDiscoReqToken()
	validation, err4 := s.EncryptCFB([]byte(token))
	hostname, err5 := os.Hostname()
	alias, err6 := s.EncryptCFB([]byte(hostname))

	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || err6 != nil {
		var strBldr bytes.Buffer
		strBldr.WriteString("Error while encryption Discovery Response:\n")

		if err1 != nil {
			strBldr.WriteString("\tServer Ip error: " + err1.Error() + "\n")
		}

		if err2 != nil {
			strBldr.WriteString("\tServer Port error: " + err2.Error() + "\n")
		}

		if err3 != nil {
			strBldr.WriteString("\tToken Generate error: " + err3.Error() + "\n")
		}

		if err4 != nil {
			strBldr.WriteString("\tPackage Validation error: " + err4.Error() + "\n")
		}

		if err5 != nil {
			strBldr.WriteString("\tHostname error: " + err5.Error() + "\n")
		}

		if err6 != nil {
			strBldr.WriteString("\tAlias error: " + err6.Error() + "\n")
		}

		return discomodel.DiscoveryPkg{}, errors.New(strBldr.String())
	}

	return discomodel.DiscoveryPkg{Type: discomodel.DISCOVERY_PACKAGE,
		PkgValidation: s.HideLengthInCFBEncryptedString(validation, len(token)),
		AppServerIp:   s.HideLengthInCFBEncryptedString(AppServerIp, len(appIp)),
		AppServerPort: s.HideLengthInCFBEncryptedString(port, len(appPort)),
		Alias:         s.HideLengthInCFBEncryptedString(alias, len(hostname))}, nil
}

// building udp response connection
// target - requester
func (this *DefaultDiscoveryHandler) GetResponseUdpConnection(destinationIp string, destinationPort string) (net.Conn, error) {
	RequesterAddr, err1 := net.ResolveUDPAddr(discomodel.CONNECTION_TYPE_UDP,
		utils.GetConnectionString(destinationIp,
			destinationPort))
	ServerLocalAddr, err2 := net.ResolveUDPAddr(discomodel.CONNECTION_TYPE_UDP,
		discomodel.DEFAULT_LOCAL_BROADCAST_CONNECTION_STRING)

	if err1 != nil || err2 != nil {
		var strBldr bytes.Buffer
		strBldr.WriteString("Error while building Response Udp Connection:\n")

		if err1 != nil {
			strBldr.WriteString("\tResolve Requester Udp Addr error: " + err1.Error() + "\n")
		}

		if err2 != nil {
			strBldr.WriteString("\tResolve Local Addr error: " + err2.Error() + "\n")
		}

		return nil, errors.New(strBldr.String())
	}

	return net.DialUDP(discomodel.CONNECTION_TYPE_UDP,
		ServerLocalAddr,
		RequesterAddr)
}

// helper method for decrypting cfb encrypted string
func decryptCFBString(encrypted string, s *security.Security) (string, error) {
	// will get the length in form PATTERN{lengthValue}PATTERN
	hiddenLength, e1 := s.FindLengthInCFBEncryptedString(encrypted)
	// will get rid of PATTERN in hidden length so the result will be {lengthValue}
	cleanLength, e1 := s.RemovePatternAttrsFromLength(hiddenLength)
	/* data looks like {encrypted data first half}PATTERN{lengthValue}PATTERN{encrypted data second half}
	   this operation will return {encrypted data}*/
	cleanEncrypted := s.RemoveLengthFromCFBEncryptedData(encrypted, hiddenLength)
	decrypted, e1 := s.DecryptCFB([]byte(cleanEncrypted), cleanLength)
	return decrypted, e1
}
