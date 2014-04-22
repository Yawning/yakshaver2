/*
 * ssh.go - SSH Handshake Classifier.
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

package dpi

import (
	"bytes"
	"strings"
)

var SshProtocol = "ssh"

type SshEngine struct {
	// Is it still possible to match
	maybe bool
}

func (e SshEngine) Make() Engine {
	instance := new(SshEngine)
	instance.maybe = true
	return instance
}

func (e SshEngine) Name() *string {
	return &SshProtocol
}

const (
	bannerExpected = "SSH-2.0"
	bannerHdrLength = len(bannerExpected) // "SSH-2.0"
)


// Classify SSH 2.0 Handshakes.
func (e SshEngine) Match(remoteAddr string, buf *bytes.Buffer) (bool, error) {
	b := buf.Bytes()
	sz := len(b)

	if !e.maybe {
		return false, nil
	}

	if sz < bannerHdrLength {
		return false, ErrAgain
	}

	// Look for the banner.
	banner := buf.String()
	if strings.HasPrefix(banner, bannerExpected) {
		return true, nil
	}

	// XXX: Ensure that the rest of the buffer till the newline is printable
	// ASCII.

	e.maybe = false
	return false, nil
}

func init() {
	var factory SshEngine
	Register(factory)
}
