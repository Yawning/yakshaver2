## yakshaver2 - Super Yak Shaver II Turbo
#### Yawning Angel (yawning at torproject dot org)

### What?

This is a knockoff of [sslh](http://www.rutschle.net/tech/sslh.shtml), written
in Go, primarily for sharing port 443 with Tor Pluggable Transports.

The notable differences between sslh and yakshaver2 are:
 * Go is used as the implementation language.
 * Instead of select() or fork(), goroutines are used.  This should be a
   scalability gain.
 * yakshaver2 examines the ClientHello in more detail.

### Why?

 * All the cool kids are using Go these days, and I wanted to see what the fuss
   was about.  Some people write "Hello World", I write daemons.
 * sslh's TLS detection is inadequate when one of the potential protocols is
   designed to mimic random noise (0x16 0x03 [0x00 - 0x03] can be valid
   UniformDH public keys).  The DPI used here is somewhat better and should
   lead to significantly less (though non-zero) false positives.
 * DPI for the forces of good, not evil.

### TODO

 * Give a lot of thought into how to defend against active probing attacks.
   To be honest, I'm not sure this matters since the PT should defend against
   it on their own.  Yes this is a hint that you should use ScrambleSuit over
   obfs3.
 * Transparent proxy support (IP_TRANSPARENT/IP_BINDANY).
 * DPI routines for other protocols.

### WON'T DO

 * I do not care about Windows or Darwin, though it will probably work.
 * I do not care that the name is dumb.
 * I do not care that the SSH detection only really works when the client talks
   first.  OpenSSH works for me, and clients are allowed to just send the banner
   per the RFC.

