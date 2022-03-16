package blockv

import (
	"crypto/md5"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeygen(t *testing.T) {
	m, err := NewMe("0.0.0.0:8000", "", "")
	if err != nil {
		t.Fatal(err)
	}
	err = m.Close()
	if err != nil {
		t.Fatal(err)
	}
	pubkey, err := m.PublicKey() // 57 bytes
	if err != nil {
		t.Fatal(err)
	}
	privkey, err := m.PrivateKey() // 28 bytes
	if err != nil {
		t.Fatal(err)
	}
	m, err = NewMe("0.0.0.0:8000", pubkey, privkey)
	if err != nil {
		t.Fatal(err)
	}
	err = m.Close()
	if err != nil {
		t.Fatal(err)
	}
	mpub, err := m.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, pubkey, mpub)
	mpriv, err := m.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, privkey, mpriv)
}

func TestSign(t *testing.T) {
	m, err := NewMe("0.0.0.0:8000", "", "")
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
	t.Fail()
}
