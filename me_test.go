package blockv

import (
	"crypto/md5"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeygen(t *testing.T) {
	m, err := NewMe("test", "0.0.0.0:8000", "", "", "pwd", "")
	if err != nil {
		t.Fatal(err)
	}
	err = m.Close()
	if err != nil {
		t.Fatal(err)
	}
	pubkey := m.PublicKey()   // 57 bytes
	privkey := m.PrivateKey() // 28 bytes
	m, err = NewMe("test", "0.0.0.0:8000", pubkey, privkey, "pwd", "")
	if err != nil {
		t.Fatal(err)
	}
	err = m.Close()
	if err != nil {
		t.Fatal(err)
	}
	mpub := m.PublicKey()
	assert.Equal(t, pubkey, mpub)
	mpriv := m.PrivateKey()
	assert.Equal(t, privkey, mpriv)
}

func TestSign(t *testing.T) {
	m, err := NewMe("test", "0.0.0.0:8000", "", "", "pwd", "")
	if err != nil {
		t.Fatal(err)
	}
	err = m.Close()
	if err != nil {
		t.Fatal(err)
	}
	md := md5.Sum([]byte("hello world!"))
	sig, err := m.Sign(md[:])
	if err != nil {
		t.Fatal(err)
	}
	t.Log(len(sig))
	assert.Equal(t, true, Verify(m.pubk[:], md[:], sig))
}
