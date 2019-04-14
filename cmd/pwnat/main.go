package main

import (
	"../.."
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ABool is an atomic boolean.
type ABool struct{ flag int32 }

// Put sets the value of the ABool's flag.
func (b ABool) Put(p bool) {
	var i int32
	if p {
		i = 1
	}
	atomic.StoreInt32(&(b.flag), int32(i))
}

// Get retrieves and returns the value of the ABool's flag.
func (b ABool) Get() bool {
	if atomic.LoadInt32(&(b.flag)) != 0 {
		return true
	}
	return false
}

var (
	svAddr    string
	psk       string
	ntpHost   = "time.google.com"
	picket    pwnat.Picket
	accepted  = ABool{}
	accepting sync.Map
)

func onPeerDiscovered(peer net.IPAddr) {
	fmt.Fprintf(os.Stderr, "peer discovered: %s\n", peer)
	// don't attempt to establish multiple connections with any peer, or to
	// establish more than one connection
	if _, ok := accepting.Load(peer); accepted.Get() || ok {
		return
	}
	deadline := time.Now().Add(time.Minute)
	accepting.Store(peer, struct{}{})
	go func() {
		for time.Now().Before(deadline) {
			picket.Telegraph(&peer)
			time.Sleep(500 * time.Millisecond)
		}
		accepting.Delete(peer)
	}()
	conn, err := picket.SyncOpen(peer, 50*time.Millisecond, &deadline)
	defer conn.Close()
	if err != nil {
		panic(err)
	}
	// declare victory
	fmt.Fprintf(os.Stderr, "peer connected: %s\n", peer)
	accepted.Put(true)
	go io.Copy(conn, os.Stdin)
	io.Copy(os.Stdout, conn)
	// disconnect on EOF, start accepting connections again
	accepted.Put(false)
}

func main() {
	flag.StringVar(&svAddr, "c", "", "Server address to petition as a client.")
	flag.StringVar(&ntpHost, "ntp", "time.google.com", "NTP host to query.")
	flag.StringVar(&psk, "psk", "go",
		"Pre-shared key used to identify valid clients."+
			" Don't make this anything sensitive!")
	flag.Parse()
	picket = pwnat.Picket{PSK: psk, NTP: ntpHost}

	// If not serving, i.e. simply waiting for another connection regardless of
	// who it happens to be, repeatedly telegraph the remote host to signal our
	// intentions and authenticate ourselves
	if svAddr != "" {
		remote := net.ParseIP(svAddr)
		if remote == nil {
			ips, err := net.LookupIP(svAddr)
			if err != nil {
				panic(fmt.Errorf("resolve hostname: %s", err))
			}
			remote = ips[0]
		}
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			for range ticker.C {
				err := picket.Telegraph(&net.IPAddr{IP: remote, Zone: ""})
				if err != nil {
					panic(fmt.Errorf("echo loop: %s", err))
				}
			}
		}()
	}
	// Announce ourselves to the NAT and attempt a PSK check and simultaneous
	// open() on the synchro ticker for all remote announcements. This must be
	// done on both client and server because they each use ICMP Time Exceeded
	// responses to identify each other.
	ticker := time.NewTicker(500 * time.Millisecond)
	for range ticker.C {
		err := picket.Echo(nil, onPeerDiscovered)
		if err != nil {
			panic(fmt.Errorf("echo loop: %s", err))
		}
	}
}
