package blockv

import (
	"net"

	tea "github.com/fumiama/gofastTEA"
)

type Peer struct {
	conn *net.UDPConn
	dst  *net.UDPAddr
	t    *tea.TEA
}

func NewPeer(conn *net.UDPConn, dst *net.UDPAddr, t *tea.TEA) Peer {
	return Peer{conn: conn, dst: dst, t: t}
}

func (peer *Peer) Send(m Message) (err error) {
	dat, err := FormatDatagram(m, peer.t)
	if err != nil {
		return
	}

	_, err = peer.conn.WriteTo(dat, peer.dst)
	return
}

func (peer *Peer) GetReply(m Message) (rep Message, err error) {
	dat, err := FormatDatagram(m, peer.t)
	if err != nil {
		return
	}
	_, err = peer.conn.WriteTo(dat, peer.dst)
	if err != nil {
		return
	}
	dat = make([]byte, 65536)
	n, err := peer.conn.Read(dat)
	if err != nil {
		return
	}
	return ParseDatagram(dat[:n], peer.t)
}
