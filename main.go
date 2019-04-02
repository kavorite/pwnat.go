package pwnat

import (
	"net"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

var (
	svAddr string
	psk          string
	ntpHost      = "time.google.com"
	picket 		 Picket
	accepting    sync.Map
)

func onPeerDiscovered(peer net.IPAddr) {
	if _, ok := accepting.Load(peer); ok {
		return
	}
	accepting.Store(peer, struct{}{})
	deadline := time.Now().Add(time.Minute)
	go func() {
		for time.Now().Before(deadline) {
			picket.Telegraph(&peer)
		}
	}()
	go func() {
		time.Sleep(time.Minute)
		accepting.Delete(peer)
	}()
	conn, err := picket.SyncOpen(peer, 50*time.Millisecond, &deadline)
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(os.Stderr, "%s\n", peer)
	go io.Copy(os.Stdout, conn)
	io.Copy(conn, os.Stdin)
}

func main() {
	flag.StringVar(&svAddr, "c", "", "Server address to petition as a client.")
	flag.StringVar(&ntpHost, "ntp", "NTP server", "NTP host to query.")
	flag.StringVar(&psk, "psk", "go",
		"Pre-shared key used to identify valid clients."+
			" Don't make this anything sensitive, as it won't be encrypted"+
			" or obfuscated in any way.")
	flag.Parse()
	picket = Picket{PSK: psk, NTP: ntpHost}
	// if we're serving, wait for clients to connect, telegraph them, then
	// attempt simultaneous open() on the synchro ticker for some predetermined
	// TTL.
	if svAddr == "" {
		picket.Listen(nil, onPeerDiscovered)
		fmt.Fprintln(os.Stderr, "listening on all interfaces")
	} else {
		remote := net.ParseIP(svAddr)
		if remote == nil {
			ips, err := net.LookupIP(svAddr)
			if err != nil {
				panic(fmt.Errorf("resolve hostname: %s", err))
			}
			remote = ips[0]
		}
		picket.Telegraph(&net.IPAddr{IP: remote, Zone: ""})
	}
}
