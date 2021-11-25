package vrrp

import (
	"fmt"
	"net"

	"syscall"

	"github.com/trxa/VRRP-go/logger"
)

type ipConnection interface {
	WriteMessage(*VRRPPacket, net.IP) error
	ReadMessage() (*VRRPPacket, error)
}

type ipv4Con struct {
	buffer []byte
	local  net.IP
	conn   *net.IPConn
}

func createIPConnection(local net.IP) (*net.IPConn, error) {
	var conn *net.IPConn
	var errOfListenIP error
	//redundant
	//todo simplify here
	if local.IsLinkLocalUnicast() {
		var itf, errOfFind = findInterfacebyIP(local)
		if errOfFind != nil {
			return nil, fmt.Errorf("ipConnection: can't find zone info of %v", local)
		}
		conn, errOfListenIP = net.ListenIP("ip:112", &net.IPAddr{IP: local, Zone: itf.Name})
	} else {
		conn, errOfListenIP = net.ListenIP("ip:112", &net.IPAddr{IP: local})
	}
	if errOfListenIP != nil {
		return nil, errOfListenIP
	}
	var fd, errOfGetFD = conn.File()
	if errOfGetFD != nil {
		return nil, errOfGetFD
	}
	defer fd.Close()
	//set hop limit
	if errOfSetHopLimit := syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IP, syscall.IP_TTL, vrrpTTL); errOfSetHopLimit != nil {
		return nil, fmt.Errorf("ipConnection: %v", errOfSetHopLimit)
	}
	//set tos
	if errOfSetTOS := syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IP, syscall.IP_TOS, 7); errOfSetTOS != nil {
		return nil, fmt.Errorf("ipConnection: %v", errOfSetTOS)
	}
	logger.GLoger.Printf(logger.INFO, "IP virtual connection established %v ==> any", local)
	return conn, nil
}

func newIPv4Conn(local net.IP) ipConnection {
	var conn, errOfMakeIPConn = createIPConnection(local)
	if errOfMakeIPConn != nil {
		panic(errOfMakeIPConn)
	}
	return &ipv4Con{
		buffer: make([]byte, 2048),
		local:  local,
		conn:   conn,
	}

}

func (conn *ipv4Con) WriteMessage(packet *VRRPPacket, remote net.IP) error {
	if _, err := conn.conn.WriteTo(packet.ToBytes(), &net.IPAddr{IP: remote}); err != nil {
		return fmt.Errorf("ipv4Con.WriteMessage: %v", err)
	}
	return nil
}

func (conn *ipv4Con) ReadMessage() (*VRRPPacket, error) {
	var n, errOfRead = conn.conn.Read(conn.buffer)
	if errOfRead != nil {
		return nil, fmt.Errorf("ipv4Con.ReadMessage: %v", errOfRead)
	}
	if n < 20 {
		return nil, fmt.Errorf("ipv4Con.ReadMessage: IP datagram length %v too small", n)
	}
	var hdrlen = (int(conn.buffer[0]) & 0x0f) << 2
	if hdrlen > n {
		return nil, fmt.Errorf("ipv4Con.ReadMessage: the header length %v is lagger than total length %V", hdrlen, n)
	}
	if conn.buffer[8] != 255 {
		return nil, fmt.Errorf("ipv4Con.ReadMessage: the TTL of IP datagram carring VRRP advertisment must equal to 255")
	}
	if advertisement, errOfUnmarshal := FromBytes(conn.buffer[hdrlen:n]); errOfUnmarshal != nil {
		return nil, fmt.Errorf("ipv4Con.ReadMessage: %v", errOfUnmarshal)
	} else {
		if VRRPVersion(advertisement.GetVersion()) != VRRPv3 {
			return nil, fmt.Errorf("ipv4Con.ReadMessage: received an advertisement with %s", VRRPVersion(advertisement.GetVersion()))
		}
		var pshdr PseudoHeader
		pshdr.Saddr = net.IPv4(conn.buffer[12], conn.buffer[13], conn.buffer[14], conn.buffer[15]).To16()
		pshdr.Daddr = net.IPv4(conn.buffer[16], conn.buffer[17], conn.buffer[18], conn.buffer[19]).To16()
		pshdr.Protocol = vrrpIPProtocolNumber
		pshdr.Len = uint16(n - hdrlen)
		if !advertisement.ValidateCheckSum(&pshdr) {
			return nil, fmt.Errorf("ipv4Con.ReadMessage: validate the check sum of advertisement failed")
		} else {
			advertisement.Pshdr = &pshdr
			return advertisement, nil
		}
	}
}

func findIPbyInterface(itf *net.Interface) (net.IP, error) {
	var addrs, errOfListAddrs = itf.Addrs()
	if errOfListAddrs != nil {
		return nil, fmt.Errorf("findIPbyInterface: %v", errOfListAddrs)
	}
	for index := range addrs {
		var ipaddr, _, errOfParseIP = net.ParseCIDR(addrs[index].String())
		if errOfParseIP != nil {
			return nil, fmt.Errorf("findIPbyInterface: %v", errOfParseIP)
		}
		if ipaddr.To4() != nil {
			if ipaddr.IsGlobalUnicast() {
				return ipaddr, nil
			}
		}
	}
	return nil, fmt.Errorf("findIPbyInterface: can not find valid IP addrs on %v", itf.Name)
}

func findInterfacebyIP(ip net.IP) (*net.Interface, error) {
	if itfs, errOfListInterface := net.Interfaces(); errOfListInterface != nil {
		return nil, fmt.Errorf("findInterfacebyIP: %v", errOfListInterface)
	} else {
		for index := range itfs {
			if addrs, errOfListAddrs := itfs[index].Addrs(); errOfListAddrs != nil {
				return nil, fmt.Errorf("findInterfacebyIP: %v", errOfListAddrs)
			} else {
				for index1 := range addrs {
					var ipaddr, _, errOfParseIP = net.ParseCIDR(addrs[index1].String())
					if errOfParseIP != nil {
						return nil, fmt.Errorf("findInterfacebyIP: %v", errOfParseIP)
					}
					if ipaddr.Equal(ip) {
						return &itfs[index], nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("findInterfacebyIP: can't find the corresponding interface of %v", ip)
}
