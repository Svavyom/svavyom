// Package provtest builds fake-but-valid qcow2 images for tests. It is imported only by test code.
package provtest

import "encoding/binary"

// Qcow2 returns a minimal valid qcow2 version 3 header (no backing file, no encryption, 64 KiB clusters, 64 MiB virtual size)
// followed by body, so that two different bodies are two different images.
func Qcow2(body string) []byte {
	h := make([]byte, 72)
	copy(h, []byte{'Q', 'F', 'I', 0xfb})
	binary.BigEndian.PutUint32(h[4:], 3)
	binary.BigEndian.PutUint32(h[20:], 16)
	binary.BigEndian.PutUint64(h[24:], 64<<20)
	return append(h, body...)
}

// ISO returns a minimal ISO 9660 image: sixteen empty sectors, then a primary volume descriptor carrying the "CD001" identifier. body makes the
// bytes (and therefore the digest) distinct.
func ISO(body string) []byte {
	b := make([]byte, 32768+2048)
	b[32768] = 1
	copy(b[32769:], "CD001")
	b[32768+6] = 1
	copy(b[32768+40:], body)
	return b
}
