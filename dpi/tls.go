/*
 * tls.go - TLS Handshake Classifier.
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
	"log"
)

var TlsProtocol = "tls"
var ErrFragmentedRecord = errors.New("TLS Record is Fragmented")

type TlsEngine struct {
	// Is it still possible to match
	maybe bool
}

func (e TlsEngine) Make() Engine {
	instance := new(TlsEngine)
	instance.maybe = true
	return instance
}

func (e TlsEngine) Name() *string {
	return &TlsProtocol
}

const (
	recordHdrLength    = 5
	handshakeHdrLength = 4

	contentTypeHandshake = 0x16
	tlsVersionSsl30      = 0x0300
	tlsVersionTls10      = 0x0301
	tlsVersionTls11      = 0x0302
	tlsVersionTls12      = 0x0303
	tlsRecordLengthMax   = 0x4000

	msgTypeClientHello = 0x01
	minClientHelloLength = 2 + 4 + 28 + 1
	maxSessionIdLength = 32
	minCipherSuitesLength = 2 + 2
	minCompressionMethodLength = 2
)

func validateClientHelloOpener(remoteAddr string, b []byte) (bool, int) {
	sz := len(b)

	// Check for extremely truncated ClientHellos.
	if sz < minClientHelloLength {
		log.Printf("[%s]: Invalid ClientHello length: 0x%x\n", remoteAddr, sz)
		return false, 0
	}

	// ProtocolVersion client_version
	tls_ver := uint16(b[0])<<8 | uint16(b[1])
	if tls_ver < tlsVersionSsl30 || tls_ver > tlsVersionTls12 {
		log.Printf("[%s]: Invalid (ClientHello) ProtocolVersion: 0x%x\n",
			remoteAddr, tls_ver)
		return false, 0
	}

	// SessionID session_id
	session_id_len := int(b[34])
	if session_id_len > maxSessionIdLength {
		log.Printf("[%s]: Invalid SessionID length: 0x%x\n",
			remoteAddr, session_id_len)
		return false, 0
	}
	if sz < minClientHelloLength + session_id_len {
		log.Printf("[%s]: Invalid SessionID, truncated\n", remoteAddr)
		return false, 0
	}

	// There's still more to examine.
	if sz == minClientHelloLength + session_id_len {
		log.Printf("[%s]: Missing CipherSuites/CompressionMethods\n",
				   remoteAddr)
		return false, 0
	}

	return true, minClientHelloLength + session_id_len
}

func validateClientHelloCipherSuites(remoteAddr string, b []byte) (bool, int) {
	sz := len(b)

	if sz < minCipherSuitesLength {
		log.Printf("[%s]: Invalid CipherSuites, truncated: 0x%x\n",
				   remoteAddr, sz)
		return false, 0
	}

	// Validate CipherSuites.  Don't check that they're known, only that they
	// are all present and the length makes sense.
	cipher_suites_len := int(uint16(b[0])<< 8 | uint16(b[1]))
	if cipher_suites_len < 2 || cipher_suites_len & 1 == 1 {
		log.Printf("[%s]: Invalid CipherSuites length: 0x%x\n",
				   remoteAddr, cipher_suites_len)
		return false, 0
	}
	if sz < 2 + cipher_suites_len {
		log.Printf("[%s]: Invalid CipherSuites, truncated\n", remoteAddr)
		return false, 0
	}

	// There's still more to examine.
	if sz == 2 + cipher_suites_len {
		log.Printf("[%s]: Missing CompressionMethods\n", remoteAddr)
		return false, 0
	}

	return true, 2 + cipher_suites_len
}

func validateClientHelloCompressionMethods(remoteAddr string, b []byte) (bool, int) {
	sz := len(b)

	if sz < minCompressionMethodLength { // At least 1 (null) compression
		log.Printf("[%s]: Invalid CompressionMethods, truncated: 0x%x\n",
				   remoteAddr, sz)
		return false, 0
	}

	// Validate CompressionMethods.  Likewise, only check that the expected
	// number are present.
	comp_method_len := int(b[0])
	if comp_method_len < 1 {
		log.Printf("[%s]: Invalid CompressionMethod length: 0x%x\n",
				   remoteAddr, comp_method_len)
		return false, 0
	}
	if sz < 1 + comp_method_len {
		log.Printf("[%s]: Invalid CompressionMethods, truncated\n", remoteAddr)
		return false, 0
	}

	return true, 1 + comp_method_len
}

func validateClientHelloExtensions(remoteAddr string, b []byte) (bool) {
	sz := len(b)

	// Validate extensions.  Just check that the extensions length extends to
	// the end of the ClientHello for now.  Parse the TLV values later.
	if sz < 2 {
		log.Printf("[%s]: Invalid Extensions, truncated: 0x%x\n",
				   remoteAddr, sz)
		return false
	}
	extensions_len := int(uint16(b[0])<< 8 | uint16(b[1]))
	if sz != 2 + extensions_len {
		log.Printf("[%s]: Invalid Extensions, truncated\n", remoteAddr)
		return false
	}

	return true
}

// Validate a "complete" ClientHello.
func validateClientHello(remoteAddr string, b []byte) bool {
	sz := len(b)

	ok, skip := validateClientHelloOpener(remoteAddr, b)
	if !ok {
		return false
	}
	sz -= skip
	b = b[skip:]

	ok, skip = validateClientHelloCipherSuites(remoteAddr, b)
	if !ok {
		return false
	}
	sz -= skip
	b = b[skip:]

	ok, skip = validateClientHelloCompressionMethods(remoteAddr, b)
	if !ok {
		return false
	}
	sz -= skip
	if sz == 0 {
		// Extensions are optional, though *everyone* uses them.
		return true;
	}
	b = b[skip:]

	return validateClientHelloExtensions(remoteAddr, b)

	return true
}

// Classify SSL 3.0/TLS [1.0, 1.1, 1.2] handshakes.
func (e TlsEngine) Match(remoteAddr string, buf *bytes.Buffer) (bool, error) {
	b := buf.Bytes()
	sz := len(b)

	if !e.maybe {
		return false, nil
	}

	// Match the outer TLSPlaintext envelope.
	if sz < recordHdrLength {
		return false, ErrAgain
	}
	if b[0] != contentTypeHandshake {
		log.Printf("[%s]: Invalid ContentType: 0x%x\n", remoteAddr, b[0])
		e.maybe = false
		return false, nil
	}
	tls_ver := uint16(b[1])<<8 | uint16(b[2])
	if tls_ver < tlsVersionSsl30 || tls_ver > tlsVersionTls12 {
		log.Printf("[%s]: Invalid ProtocolVersion: 0x%x\n", remoteAddr,
			tls_ver)
		e.maybe = false
		return false, nil
	}
	rec_len := int(uint16(b[3])<<8 | uint16(b[4]))
	if rec_len > tlsRecordLengthMax || rec_len == 0 {
		log.Printf("[%s]: Invalid (Record) length: 0x%x\n", remoteAddr,
			rec_len)
		e.maybe = false
		return false, nil
	}

	// Ensure that the entire Record is present.
	if sz < rec_len+recordHdrLength {
		return false, ErrAgain
	}

	// Technically each record can be as small as 1 byte, but most SSL/TLS
	// implementations will choke on that.  As a matter of fact, just drop
	// the connection whenever it looks like it *could* be a fragmented
	// ClientHello because chances are the peer is being actively
	// malicious.
	//
	// XXX: This *could* be a valid obfuscated handshake, but it's kind of
	// unlikely, and it's not possible to do much with this without
	// overcomplicating the classifier to support fragment reassembly.
	if rec_len < handshakeHdrLength {
		log.Printf("[%s]: Invalid (Record) length: 0x%x\n", remoteAddr,
			rec_len)
		e.maybe = false
		return false, ErrFragmentedRecord
	}

	// Validate the Handshake message header.
	if b[5] != msgTypeClientHello {
		log.Printf("[%s]: Invalid MessageType: 0x%x\n", remoteAddr, b[5])
		e.maybe = false
		return false, nil
	}
	hs_len := uint32(b[6])<<16 | uint32(b[7])<<8 | uint32(b[8])
	if hs_len != uint32(rec_len-handshakeHdrLength) || hs_len == 0 {
		// See note about fragment reassembly.
		log.Printf("[%s]: Invalid (Handshake) length: 0x%x\n", remoteAddr,
			hs_len)
		e.maybe = false
		return false, ErrFragmentedRecord
	}

	// Validate the ClientHello.  Since the record is guaranteed to be
	// entirely buffered, and the Handshake length is valid, any 
	// truncation past this point are either busted TLS implementations, or
	// a mismatch.
	if validateClientHello(remoteAddr, b[9:]) {
		return true, nil
	}

	e.maybe = false
	return false, nil
}

func init() {
	var factory TlsEngine
	Register(factory)
}
