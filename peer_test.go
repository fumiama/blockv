package blockv

import (
	"net"
	"sync"
	"testing"

	base14 "github.com/fumiama/go-base16384"
	"github.com/stretchr/testify/assert"
)

func TestListen(t *testing.T) {
	laddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:8000")
	if err != nil {
		t.Fatal(err)
	}
	raddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:8001")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		data := make([]byte, 16)
		ep, err := net.ListenUDP("udp", raddr)
		if err != nil {
			panic(err)
		}
		n, err := ep.Read(data)
		if err != nil {
			panic(err)
		}
		assert.Equal(t, "hello world!", base14.BytesToString(data[:n]))
		wg.Done()
	}()

	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		t.Fatal(err)
	}

	_, err = conn.Write([]byte("hello world!"))
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestEcho(t *testing.T) {
	m1, err := NewMe("test", "127.0.0.1:8000", "", "", "pwd", "")
	if err != nil {
		t.Fatal(err)
	}
	udpaddr1, err := net.ResolveUDPAddr("udp", "127.0.0.1:8000")
	if err != nil {
		t.Fatal(err)
	}
	udpaddr2, err := net.ResolveUDPAddr("udp", "127.0.0.1:8001")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", udpaddr2)
	p1 := NewPeer(conn, udpaddr1, &m1.teak)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := p1.GetReply(Message{Typ: PKTTYP_ERQ, Dat: []byte("hello world!")})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, uint8(PKTTYP_NIL), rep.Typ)
	assert.Equal(t, "hello world!", string(rep.Dat))
}
