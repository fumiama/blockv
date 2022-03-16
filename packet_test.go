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
	p, err := NewPacket(Message{PKTTYP_SET, []byte("hello world!")}, &tc)
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
	t.Log(p2.Dat)
	err = p2.Decrypt(&tc)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "hello world!", string(p2.Dat))
}

func TestPackSplice(t *testing.T) {
	tc := tea.NewTeaCipher([]byte("password"))
	p, err := NewPacket(Message{PKTTYP_SET, []byte("hello world!")}, &tc)
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
	t.Log(p2.Dat)
	err = p2.Decrypt(&tc)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "hello world!", string(p2.Dat))
}

func TestDgram(t *testing.T) {
	tc := tea.NewTeaCipher([]byte("password"))
	msg := Message{
		Typ: PKTTYP_GET,
		Dat: make([]byte, 32769),
	}
	buf, err := FormatDatagram(msg, &tc)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseDatagram(buf, &tc)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, msg, m)
}

func BenchmarkFormatDatagram(b *testing.B) {
	tc := tea.NewTeaCipher([]byte("password"))
	b.Run("16", func(b *testing.B) {
		data := make([]byte, 16)
		benchFormatDatagram(b, &tc, data)
	})
	b.Run("256", func(b *testing.B) {
		data := make([]byte, 256)
		benchFormatDatagram(b, &tc, data)
	})
	b.Run("4K", func(b *testing.B) {
		data := make([]byte, 1024*4)
		benchFormatDatagram(b, &tc, data)
	})
	b.Run("32K", func(b *testing.B) {
		data := make([]byte, 1024*32)
		benchFormatDatagram(b, &tc, data)
	})
}

func BenchmarkParseDatagram(b *testing.B) {
	tc := tea.NewTeaCipher([]byte("password"))
	b.Run("16", func(b *testing.B) {
		data := make([]byte, 16)
		benchParseDatagram(b, &tc, data)
	})
	b.Run("256", func(b *testing.B) {
		data := make([]byte, 256)
		benchParseDatagram(b, &tc, data)
	})
	b.Run("4K", func(b *testing.B) {
		data := make([]byte, 1024*4)
		benchParseDatagram(b, &tc, data)
	})
	b.Run("32K", func(b *testing.B) {
		data := make([]byte, 1024*32)
		benchParseDatagram(b, &tc, data)
	})
}

func benchFormatDatagram(b *testing.B, tc *tea.TEA, data []byte) {
	msg := Message{
		Typ: PKTTYP_GET,
		Dat: data,
	}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = FormatDatagram(msg, tc)
	}
}

func benchParseDatagram(b *testing.B, tc *tea.TEA, data []byte) {
	msg := Message{
		Typ: PKTTYP_GET,
		Dat: data,
	}
	buf, err := FormatDatagram(msg, tc)
	if err != nil {
		panic(err)
	}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseDatagram(buf, tc)
	}
}
