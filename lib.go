package pwnat

import (
	"github.com/beevik/ntp"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"hash/adler32"
	"math/rand"
	"net"
	"time"
	"fmt"
)

var (
	dFakeHost = &net.IPAddr{IP: net.IP{3, 3, 3, 3}}
)

func mkEcho(psk string) *icmp.Echo {
	hash := adler32.Checksum([]byte(psk))
	return &icmp.Echo{
		ID: rand.Int() % 0xffff,
		Seq: 0,
		Data: []byte(fmt.Sprintf("%x", hash)),
	}
}

// Picket is a class of objects used for discovering peer IPs and announcing
// remote peers' presence to a given host during initialization of tunnels.
type Picket struct {
	PSK string
	NTP string
}

// NextPort returns an OS port according to synchronized state.
func (sv Picket) NextPort(t time.Time) uint16 {
	return uint16((t.Round(time.Second*2).Unix()+1000) % 0xffff)
}

// Telegraph announces itself to another picket. This can be run concurrently
// with Listen() in order to check whether a host is accessible.
func (sv Picket) Telegraph(peer net.Addr) (err error) {
	echo, _ := mkEcho(sv.PSK).Marshal(ipv4.ICMPTypeEcho.Protocol())
	msg := icmp.Message{
		Type: ipv4.ICMPTypeTimeExceeded, Code: 0,
		Body: &icmp.TimeExceeded{
			Data: echo,
		},
	}
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return
	}
	wbuf, err := msg.Marshal(nil)
	if err != nil {
		return
	}
	_, err = conn.WriteTo(wbuf, peer)
	return
}

// SyncOpen (synchronized open()) attempts to perform simultaneous open()
// calls with a remote host using a remote time server and local state
// to establish a peer to peer connection.
// TODO: Context cancellations?
func (sv Picket) SyncOpen(remote net.IPAddr, interval time.Duration, deadline *time.Time) (conn *net.TCPConn, err error) {
	rsp, _ := ntp.Query(sv.NTP)
	t := rsp.Time.Add(rsp.RTT)
	// get preferred outbound IP
	c, err := net.Dial("tcp", "google.com:http")
	if err != nil {
		return
	} 
	laddr := c.LocalAddr().(*net.TCPAddr)
	port := int(sv.NextPort(t))
	laddr.Port = port
	raddr := net.TCPAddr{IP: remote.IP, Zone: remote.Zone, Port: port}
	time.Sleep(time.Now().Sub(t))
	for range time.NewTicker(interval).C {
		conn, err = net.DialTCP("tcp", laddr, &raddr)
		if err == nil { 
			return
		}
		if deadline != nil && t.After(*deadline) {
			return nil, fmt.Errorf("synchronized open: connection timed out")
		}
	}
	return
}

// Echo begins attempting to connect to pwnat clients on a given IP address,
// with a given fake host by sending the ICMP pilot echo. Pass `nil` for
// `fakeHost` to use 3.3.3.3 by default.
func (sv Picket) Echo(fakeHost *net.IPAddr, onDiscovered func(net.IPAddr)) (err error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	defer conn.Close()
	if err != nil {
		return
	}
	if fakeHost == nil {
		fakeHost = dFakeHost
	}
	call := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: mkEcho(sv.PSK),
	}
	wbuf, _ := call.Marshal(nil)
	if err != nil {
		return
	}
	if _, err = conn.WriteTo(wbuf, fakeHost); err != nil {
		return 
	}
	rbuf := make([]byte, 1024)
	n, peer, err := conn.ReadFrom(rbuf)
	if err != nil {
		return
	}
	read, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), rbuf[:n])
	if err != nil {
		return 
	}
	if read.Type == ipv4.ICMPTypeTimeExceeded {
		// Check whether the Time Exceeded we're getting back is the same one we sent out
		response := read.Body.(*icmp.TimeExceeded).Data
		lhash := adler32.Checksum(wbuf)
		rhash := adler32.Checksum(response)
		if lhash == rhash {
			go onDiscovered(*peer.(*net.IPAddr))
		}
	}
	return
}
