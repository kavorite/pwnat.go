package pwnat

import (
	"github.com/beevik/ntp"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"hash/adler32"
	"net"
	"time"
)

var (
	dFakeHost = &net.IPAddr{IP: net.ParseIP("3.3.3.3")}
	hasher    = adler32.New()
)

func mkEcho(psk string) *icmp.Echo {
	hasher.Write([]byte(psk))
	return &icmp.Echo{
		ID:   int(hasher.Sum32()),
		Seq:  1,
		Data: []byte("pwnat.go"),
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
	return uint16(t.Round(time.Second*2).Unix() % (0x01 << 16))
}

// Telegraph announces itself to another picket. This can be run concurrently
// with Listen() in order to check whether a host is accessible.
func (sv Picket) Telegraph(peer net.Addr) {
	echo, _ := mkEcho(sv.PSK).Marshal(ipv4.ICMPTypeEcho.Protocol())
	msg := icmp.Message{
		Type: ipv4.ICMPTypeTimeExceeded, Code: 0,
		Body: &icmp.TimeExceeded{
			Data: echo,
		},
	}
	conn, _ := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	wbuf, _ := msg.Marshal(nil)
	conn.WriteTo(wbuf, peer)
}

// SyncOpen (synchronized open()) attempts to perform simultaneous open()
// calls with a remote host using a remote time server and local state
// to establish a peer to peer connection.
// TODO: Context cancellations?
func (sv Picket) SyncOpen(remote net.IPAddr, interval time.Duration, deadline *time.Time) (conn *net.TCPConn, err error) {
	rsp, _ := ntp.Query(sv.NTP)
	t := rsp.Time.Add(rsp.RTT)
	// get preferred outbound IP
	c, err := net.Dial("tcp", "1.1.1.1:http")
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
		if (deadline != nil && t.After(*deadline)) || err == nil {
			return
		}
	}
	return
}

// Echo begins attempting to connect to pwnat clients on a given IP address,
// with a given fake host by sending the ICMP pilot echo. Pass `nil` for
// `fakeHost` to use 3.3.3.3 by default.
func (sv Picket) Echo (fakeHost *net.IPAddr, onDiscovered func(net.IPAddr)) (err error) {
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
	wbuf, err := call.Marshal(nil)
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
	if read.Type == ipv4.ICMPTypeEchoReply {
		// Check the PSK's hash against ours, and if it talks like a duck...
		echo := read.Body.(*icmp.Echo)
		hasher.Write([]byte(sv.PSK))
		if echo.ID == int(hasher.Sum32()) {
			onDiscovered(*peer.(*net.IPAddr))
		}
	}
	return
}
