package conf

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const keyLen = 32

var errBadKey = errors.New("not a WireGuard key")

// A Key is a WireGuard public key.
type Key [keyLen]byte

// ParseKey reads a key in the base64 form configuration files use.
func ParseKey(s string) (Key, error) {
	var k Key
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != keyLen {
		return k, errBadKey
	}
	copy(k[:], raw)
	return k, nil
}

func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func (k Key) IsZero() bool {
	return k == Key{}
}

// A Secret is a private or preshared key. Every fmt verb prints it as "(secret)" and JSON as {},
// so logging or encoding a Config cannot leak it. Reveal is the one way to its bytes.
type Secret struct {
	key [keyLen]byte
}

func parseSecret(s string) (Secret, error) {
	k, err := ParseKey(s)
	return Secret{key: k}, err
}

// Reveal returns the key itself, for handing to the WireGuard device and nothing else.
func (s Secret) Reveal() [keyLen]byte {
	return s.key
}

func (s Secret) IsZero() bool {
	return s.key == [keyLen]byte{}
}

func (s Secret) Format(f fmt.State, verb rune) {
	io.WriteString(f, "(secret)")
}

func (s Secret) base64() string {
	return base64.StdEncoding.EncodeToString(s.key[:])
}
