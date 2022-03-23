package blockv

import (
	"bufio"
	"crypto/elliptic"
	"encoding/json"
	"math/big"
	"net"
	"os"
	"sync"

	"github.com/1william1/ecc"
	base14 "github.com/fumiama/go-base16384"
	tea "github.com/fumiama/gofastTEA"
)

const PUB_KEY_TAIL = "㴁"

type Me struct {
	conn    *net.UDPConn
	eccp    ecc.Private
	privk   [28]byte
	pubk    [57]byte
	teak    tea.TEA
	teaks   string
	peers   map[string]*Peer
	peersmu sync.RWMutex
	storage *Storage
}

// NewMe addr such as 0.0.0.0:8000
func NewMe(storagepath, addr, pubkey, privkey, teakey, peers string) (m *Me, err error) {
	m = new(Me)
	m.storage, err = NewStorage(storagepath)
	if err != nil {
		return nil, err
	}
	if pubkey != "" && privkey != "" {
		b, err := base14.UTF82UTF16BE(base14.StringToBytes(pubkey + PUB_KEY_TAIL))
		if err != nil {
			return nil, err
		}
		m.eccp.Public, err = ecc.ParsePublicKey(elliptic.P224(), base14.Decode(b))
		if err != nil {
			return nil, err
		}
		b, err = base14.UTF82UTF16BE(base14.StringToBytes(privkey))
		if err != nil {
			return nil, err
		}
		m.eccp.D = new(big.Int)
		m.eccp.D.SetBytes(base14.Decode(b))
	} else {
		priv, err := ecc.GenerateKey(elliptic.P224())
		if err != nil {
			return nil, err
		}
		m.eccp = *priv
	}
	copy(m.privk[:], m.eccp.D.Bytes())
	copy(m.pubk[:], m.eccp.Public.Bytes())
	m.teak = tea.NewTeaCipher(base14.StringToBytes(teakey))
	m.teaks = teakey
	m.peers = make(map[string]*Peer)
	if peers != "" {
		err = json.Unmarshal(base14.StringToBytes(peers), &m.peers)
		if err != nil {
			panic(err)
		}
	}
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		panic(err)
	}
	m.conn, err = net.ListenUDP("udp", laddr)
	go m.Listen()
	return
}

// LoadMe loads config from path
func LoadMe(storagepath, configpath string) (*Me, error) {
	f, err := os.Open(configpath)
	if err != nil {
		return nil, err
	}
	s := bufio.NewScanner(f)
	var addr, pubkey, privkey, teakey, peers string
	if s.Scan() {
		addr = s.Text()
	}
	if s.Scan() {
		pubkey = s.Text()
	}
	if s.Scan() {
		privkey = s.Text()
	}
	if s.Scan() {
		teakey = s.Text()
	}
	if s.Scan() {
		peers = s.Text()

	}
	_ = f.Close()
	return NewMe(storagepath, addr, pubkey, privkey, teakey, peers)
}

func (m *Me) PrivateKey() string {
	return base14.EncodeString(base14.BytesToString(m.privk[:]))
}

func (m *Me) PublicKey() string {
	return base14.EncodeString(base14.BytesToString(m.pubk[:]))[:99]
}

func (m *Me) Sign(digest []byte) ([]byte, error) {
	return m.eccp.SignToASN1(digest)
}

func Verify(pubk, digest, signature []byte) bool {
	p, err := ecc.ParsePublicKey(elliptic.P224(), pubk)
	if err != nil {
		return false
	}
	return p.VerifyASN1(digest, signature)
}

func (m *Me) Close() error {
	return m.conn.Close()
}

// Save config to path
func (m *Me) Save(path string) error {
	pub := m.PublicKey()
	priv := m.PrivateKey()
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	f.WriteString(m.conn.LocalAddr().String())
	f.WriteString("\n")
	f.WriteString(pub)
	f.WriteString("\n")
	f.WriteString(priv)
	f.WriteString("\n")
	f.WriteString(m.teaks)
	f.WriteString("\n")
	json.NewEncoder(f).Encode(&m.peers)
	return f.Close()
}

func (m *Me) Listen() {
	data := make([]byte, 65536)
	for {
		n, addr, err := m.conn.ReadFromUDP(data)
		if err != nil {
			break
		}
		ms, err := ParseDatagram(data[:n], &m.teak)
		if err != nil {
			continue
		}
		m.peersmu.RLock()
		peer, ok := m.peers[addr.String()]
		m.peersmu.RUnlock()
		if !ok {
			p := NewPeer(m.conn, addr, &m.teak)
			m.peersmu.Lock()
			m.peers[addr.String()] = &p
			m.peersmu.Unlock()
			peer = &p
		}
		go func() {
			switch ms.Typ {
			case PKTTYP_NIL:
			case PKTTYP_GET:
				key := base14.BytesToString(ms.Dat)
				v, err := m.storage.Get(key)
				if err != nil {
					return
				}
				_ = peer.Send(Message{Typ: PKTTYP_NIL, Dat: base14.StringToBytes(v)})
			case PKTTYP_SET:
			case PKTTYP_DEL:
			case PKTTYP_LST:
			case PKTTYP_ERQ:
				_ = peer.Send(Message{Typ: PKTTYP_NIL, Dat: ms.Dat})
			}
		}()
	}
}
