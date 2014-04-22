/*
 * engine.go - Handshake Deep Packet Inspection Engine.
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
	"errors"
)

var UnknownProtocol = "unknown"
var ErrUnknownEngine = errors.New("Unknown engine")
var ErrAgain = errors.New("More data needed for DPI match")

var registeredEngines = make(map[string]Engine)

// DPI Engine interface.
type Engine interface {
	// Construct a new Engine instance.
	Make() Engine

	// A human readable name for the protocol.
	Name() *string

	// Attempt to determine if the payload in the Buffer is traffic for a given
	// protocol.
	Match(string, *bytes.Buffer) (bool, error)
}

// DPI Application interface instance.
type Matcher struct {
	engines map[string]Engine
}

// Register a protocol engine.
func Register(engine Engine) {
	registeredEngines[*engine.Name()] = engine
}

// Construct a new Matcher instance.
func MakeMatcher() *Matcher {
	matcher := new(Matcher)
	matcher.engines = make(map[string]Engine)
	return matcher
}

// Enable a protocol engine.
func (m Matcher) Enable(engine string) error {
	// UnknownProtocol is always enabled, and doesn't actually have a Engine.
	if engine == UnknownProtocol {
		return nil
	}

	factory := registeredEngines[engine]
	if factory == nil {
		return ErrUnknownEngine
	}

	m.engines[engine] = factory.Make()

	return nil
}

// Attempt to determine the protocol used for the payload.
func (m Matcher) Match(remoteAddr string, payload *bytes.Buffer) (*string, error) {
	// Iterate over the engines attempting to match the payload.  Each instance
	// is responsible for maintaning it's own state, the full handshake read so
	// far will always be provided.
	var again bool = false
	for proto, e := range m.engines {
		matched, err := e.Match(remoteAddr, payload)
		if err != nil {
			if err == ErrAgain {
				again = true
				continue
			}
			return nil, err
		}
		if matched {
			return &proto, nil
		}
	}

	// At least one engine MAY be a match in the future.
	if again {
		return nil, ErrAgain
	}

	// Every engine claims it's not a match, and won't be a match.
	return &UnknownProtocol, nil
}
