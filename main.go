package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	listenerPort uint
	psk          string
	ntpHost      = "time.google.com"
	accepting    sync.Map
)

func main() {
	flag.StringVar(&svAddr, "c", "Server address to petition as a client.")
	flag.StringVar(&ntpHost, "ntp", "NTP server", "NTP host to query.")
	flag.StringVar(&psk, "psk", "Pre-shared key", "pwnat.go",
		"Pre-shared key used to identify valid clients."+
			" Don't make this anything sensitive, as it won't be encrypted"+
			" or obfuscated in any way.")
	flag.Parse()
	picket := Picket{PSK: psk, NTP: ntpHost}
	// if we're serving, wait for clients to connect, telegraph them, then
	// attempt simultaneous open() on the synchro ticker for some predetermined
	// TTL.
	if svAddr == "" {
		picket.Listen(nil, func(peer) {
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
			go io.Copy(conn, os.Stdin)
			go io.Copy(os.Stdout, conn)
		})
	} else if listenerPort != 0 {
		sv := Server{PSK: *psk}
	} else {
		prog := os.Args[0]
		fmt.Fprintf(os.Stderr, "Usage: %s [-c addr] [-psk <pass>]", prog)
		os.Exit(1)
	}
}
