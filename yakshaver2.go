/*
 * yakshaver2.go - Main entry point.
 * Copyright (C) 2014  Yawning Angel <yawning at schwanenlied dot me>
 *
 * This file is part of yakshaver2.
 *
 * yakshaver2 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * yakshaver2 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with yakshaver2.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"yakshaver2/dpi"
)

import "code.google.com/p/gcfg"

const (
	readSize         = 1500
	readSizeMax      = readSize * 2
	handshakeTimeout = 10
	scrubbedAddr	 = "[scrubbed]"
)

type Config struct {
	General struct {
		BindAddr         string
		HandshakeTimeout int
		DisableLogScrubber bool
	}

	Unknown struct {
		Enabled   bool
		ProxyAddr string
	}

	Tls struct {
		Enabled   bool
		ProxyAddr string
	}

	Ssh struct {
		Enabled   bool
		ProxyAddr string
	}
}

var configFile = flag.String("f", "yakshaver2.gcfg", "Config file")
var cfg Config
var enabledProtocols = make(map[string]string)

// Validate a string containing an IP address + port.
func validateAddrPort(addrStr string) (bool, error) {
	_, _, err := net.SplitHostPort(addrStr)
	if err != nil {
		return false, err
	}

	return true, nil
}

// Parse and populate the Config instance.
func parseConfig() error {
	err := gcfg.ReadFileInto(&cfg, *configFile)
	if err != nil {
		return err
	}

	_, err = validateAddrPort(cfg.General.BindAddr)
	if err != nil {
		return fmt.Errorf("general.bindAddr: %s", err.Error())
	}
	if cfg.General.HandshakeTimeout == 0 {
		cfg.General.HandshakeTimeout = handshakeTimeout
	}

	// Unknown
	if cfg.Unknown.Enabled {
		_, err = validateAddrPort(cfg.Unknown.ProxyAddr)
		if err != nil {
			return fmt.Errorf("unknown.proxyAddr: %s", err.Error())
		}

		enabledProtocols[dpi.UnknownProtocol] = cfg.Unknown.ProxyAddr
	}

	//  TLS
	if cfg.Tls.Enabled {
		_, err = validateAddrPort(cfg.Tls.ProxyAddr)
		if err != nil {
			return fmt.Errorf("tls.proxyAddr: %s", err.Error())
		}

		enabledProtocols[dpi.TlsProtocol] = cfg.Tls.ProxyAddr
	}

	// SSH
	if cfg.Ssh.Enabled {
		_, err = validateAddrPort(cfg.Ssh.ProxyAddr)
		if err != nil {
			return fmt.Errorf("ssh.proxyAddr: %s", err.Error())
		}

		enabledProtocols[dpi.SshProtocol] = cfg.Ssh.ProxyAddr
	}

	return nil
}

// The actual per connection worker.
func dpiProxy(conn net.Conn) {
	var buf bytes.Buffer
	thisRead := make([]byte, readSize)
	defer conn.Close()

	remoteAddr := scrubAddress(conn.RemoteAddr().String())
	timeout := time.Now().Add(time.Duration(cfg.General.HandshakeTimeout) *
		time.Second)
	conn.SetReadDeadline(timeout)

	log.Printf("[%s]: New connection\n", remoteAddr)

	// Initialize the desired protocols.
	matcher := dpi.MakeMatcher()
	for proto, _ := range enabledProtocols {
		err := matcher.Enable(proto)
		if err != nil {
			log.Printf("[%s]: Failed to enable %s: %s\n", proto, err.Error())
			return
		}
	}

	// Buffer and inspect the initiator's stream till a match is found.
	var proto *string = nil
	for {
		// Clamp the maximum amount of data to inspect.
		if buf.Len() > readSizeMax {
			log.Printf("[%s]: Buffered handshake too large\n", remoteAddr)
			return
		}

		// Consume data from the client connection.
		sz, err := conn.Read(thisRead)
		if err != nil {
			log.Printf("[%s]: Error reading: %s\n", remoteAddr, err.Error())
			return
		}
		_, err = buf.Write(thisRead[0:sz])

		// Attempt to determine the protocol.
		proto, err = matcher.Match(remoteAddr, &buf)
		if err != nil {
			if err == dpi.ErrAgain {
				continue
			} else {
				log.Printf("[%s]: Error Matching: %s\n", remoteAddr, err.Error())
				return
			}
		}

		// If execution reaches here, we have a match.
		break
	}

	// Figure out where to proxy this connection to.
	upstreamAddr := enabledProtocols[*proto]
	if upstreamAddr == "" {
		return
	}

	log.Printf("[%s]: Protocol: %s\n", remoteAddr, *proto)

	// Clear the handshake timeout
	var zeroTime time.Time
	conn.SetReadDeadline(zeroTime)

	// Create the upstream connection.
	upstream, err := net.Dial("tcp", upstreamAddr)
	if err != nil {
		log.Printf("[%s]: Error Dialing: %s\n", remoteAddr, err.Error())
		return
	}
	defer upstream.Close()

	// Write buf to the upstream
	_, err = upstream.Write(buf.Bytes())
	if err != nil {
		log.Printf("[%s]: Error flushing handshake data: %s\n", remoteAddr,
			err.Error())
		return
	}
	buf.Reset()

	// Shove bits back and forth
	var w sync.WaitGroup
	w.Add(2)
	go func() {
		io.Copy(conn, upstream)
		w.Done()
	}()
	go func() {
		io.Copy(upstream, conn)
		w.Done()
	}()
	w.Wait()

	log.Printf("[%s]: Connection closed\n", remoteAddr)
}

// Spawn the main listener and start accepting connections.
func launchListener() {
	log.Println("Launching listener:", cfg.General.BindAddr)

	l, err := net.Listen("tcp", cfg.General.BindAddr)
	if err != nil {
		log.Fatal("launchListener(): ", err.Error())
	}
	// TODO:Drop privs here.

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println("launchListener(): ", err.Error())
			continue
		}
		go dpiProxy(conn)
	}
}

// Determine if effective uid/gid is 0 (root).
func runningAsRoot() bool {
	return 0 == os.Geteuid() || 0 == os.Getegid()
}

// Scrub IP address/ports.
func scrubAddress(addr string) string {
	if cfg.General.DisableLogScrubber {
		return addr
	}

	return scrubbedAddr
}

func main() {
	flag.Parse()

	err := parseConfig()
	if err != nil {
		log.Fatal("Config error: ", err.Error())
	}

	log.Println("bindAddr:", cfg.General.BindAddr)
	log.Println("Protocols:")
	for proto, addr := range enabledProtocols {
		log.Printf(" %s: %s\n", proto, addr)
	}

	// Ensure that the user is not trying to run this as root, since the
	// runtime does not currently support safely droping to a non-root user.
	//
	// See: https://code.google.com/p/go/issues/detail?id=1435
	if runningAsRoot() {
		log.Fatal("Cowardly refusing to run with euid/egid 0")
	}

	// Bind and listen for incoming connections.
	launchListener()
}
