package blockv

import (
	"bytes"
	"io"
	"testing"

	tea "github.com/fumiama/gofastTEA"
	"github.com/stretchr/testify/assert"
)

func TestPackCopy(t *testing.T) {
	tc := tea.NewTeaCipher([]byte("password"))
	p, err := NewPacket(PKTTYP_SET, []byte("hello world!"), &tc)
	if err != nil {
		t.Fatal(err)
	}
	buf := bytes.NewBuffer(nil)
	_, err = io.Copy(buf, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(buf.Len(), buf.Bytes())
	p2 := &Packet{}
	_, err = io.Copy(p2, bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, p.len, p2.len)
	assert.Equal(t, p.typ, p2.typ)
	assert.Equal(t, p.md5, p2.md5)
	assert.Equal(t, p.dat, p2.dat)
	t.Log(p2.Dat)
	assert.Equal(t, "hello world!", string(tc.Decrypt(p2.Dat)))
}

func TestPackSplice(t *testing.T) {
	tc := tea.NewTeaCipher([]byte("password"))
	p, err := NewPacket(PKTTYP_SET, []byte("hello world!"), &tc)
	if err != nil {
		t.Fatal(err)
	}
	buf := bytes.NewBuffer(nil)
	_, err = p.WriteTo(buf)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(buf.Len(), buf.Bytes())
	p2 := &Packet{}
	_, err = p2.ReadFrom(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, p.len, p2.len)
	assert.Equal(t, p.typ, p2.typ)
	assert.Equal(t, p.md5, p2.md5)
	assert.Equal(t, p.dat, p2.dat)
	t.Log(p2.Dat)
	assert.Equal(t, "hello world!", string(tc.Decrypt(p2.Dat)))
}
