package blockv

import (
	"bufio"
	"crypto/elliptic"
	"math/big"
	"net"
	"os"

	"github.com/1william1/ecc"
	base14 "github.com/fumiama/go-base16384"
)

const PUB_KEY_TAIL = "㴁"

type Me struct {
	conn  net.PacketConn
	eccp  ecc.Private
	privk [28]byte
	pubk  [57]byte
}

// NewMe addr such as 0.0.0.0:8000
func NewMe(addr, pubkey, privkey string) (m *Me, err error) {
	m = new(Me)
	if pubkey != "" && privkey != "" {
		b, err := base14.UTF82utf16be(base14.StringToBytes(pubkey + PUB_KEY_TAIL))
		if err != nil {
			return nil, err
		}
		m.eccp.Public, err = ecc.ParsePublicKey(elliptic.P224(), base14.Decode(b))
		if err != nil {
			return nil, err
		}
		b, err = base14.UTF82utf16be(base14.StringToBytes(privkey))
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
	m.conn, err = net.ListenPacket("udp", addr)
	return
}

// LoadMe loads config from path
func LoadMe(path string) (*Me, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	s := bufio.NewScanner(f)
	var addr, pubkey, privkey string
	if s.Scan() {
		addr = s.Text()
	}
	if s.Scan() {
		pubkey = s.Text()
	}
	if s.Scan() {
		privkey = s.Text()
	}
	_ = f.Close()
	return NewMe(addr, pubkey, privkey)
}

func (m *Me) PrivateKey() (string, error) {
	b, err := base14.UTF16be2utf8(base14.Encode(m.privk[:]))
	if err != nil {
		return "", err
	}
	return base14.BytesToString(b), nil
}

func (m *Me) PublicKey() (string, error) {
	b, err := base14.UTF16be2utf8(base14.Encode(m.pubk[:]))
	if err != nil {
		return "", err
	}
	b = b[:len(b)-3]
	return base14.BytesToString(b), nil
}

func (m *Me) Sign(digest []byte) ([]byte, error) {
	return m.eccp.SignToASN1(digest)
}

func (m *Me) Verify(pubk, digest, signature []byte) bool {
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
	pub, err := m.PublicKey()
	if err != nil {
		return err
	}
	priv, err := m.PrivateKey()
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	f.WriteString(m.conn.LocalAddr().String())
	f.WriteString("\n")
	f.WriteString(pub)
	f.WriteString("\n")
	f.WriteString(priv)
	return f.Close()
}

func (m *Me) Listen() {
	var err error
	for err == nil {

	}
}
