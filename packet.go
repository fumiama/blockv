package blockv

import (
	"crypto/md5"
	"errors"
	"io"
	"unsafe"

	tea "github.com/fumiama/gofastTEA"
)

const (
	PKTTYP_NIL = iota // raw data
	PKTTYP_GET        // get value (a block) by key
	PKTTYP_SET        // set value (a block) of key
	PKTTYP_DEL        // del value (a block) of key
	PKTTYP_LST        // list all peers
	PKTTYP_ERQ        // echo request
)

const (
	PKT_HEAD_LEN = 1 + 1 + 16
	PKT_DATA_LEN = 256
)

type Packet struct {
	len uint8              // len of dat
	typ uint8              // one of PKTTYP
	md5 [16]byte           // the dat's md5 before encrypt
	dat [PKT_DATA_LEN]byte // content depends on typ
	ptr int16              // progress of read/write
	Dat []byte             // an easy-to-use pointer of dat
	io.Reader
	io.ReaderFrom
	io.Writer
	io.WriterTo
}

type Message struct {
	Typ uint8
	Dat []byte
}

func NewPacket(m Message, t *tea.TEA) (p *Packet, err error) {
	if len(m.Dat) > 238 {
		err = errors.New("data is too long")
		return
	}
	p = SelectPacket()
	p.len = uint8(t.EncryptTo(m.Dat, p.dat[:]))
	p.typ = m.Typ
	p.md5 = md5.Sum(m.Dat)
	return
}

func FormatDatagram(m Message, t *tea.TEA) (data []byte, err error) {
	w := SelectWriter()
	defer w.put()
	p := SelectPacket()
	defer PutPacket(p)
	for len(m.Dat) > 0 {
		n := 238
		if len(m.Dat) < 238 {
			n = len(m.Dat)
		}
		p.len = uint8(t.EncryptTo(m.Dat[:n], p.dat[:]))
		p.typ = m.Typ
		p.md5 = md5.Sum(m.Dat[:n])
		_, err := io.Copy(w, p)
		p.ptr = 0
		if err != nil {
			return nil, err
		}
		m.Dat = m.Dat[n:]
	}
	data = append(data, w.Bytes()...)
	return
}

func ParseDatagram(data []byte, t *tea.TEA) (m Message, err error) {
	w := SelectWriter()
	defer w.put()
	p := SelectPacket()
	defer PutPacket(p)
	for len(data) > 0 {
		cnt := 0
		cnt, err = p.Write(data)
		if err != nil {
			return
		}
		data = data[cnt:]
		err = p.Decrypt(t)
		if err != nil {
			return
		}
		if m.Typ == PKTTYP_NIL {
			m.Typ = p.typ
		}
		w.Write(p.Dat)
		p.len = 0
		p.ptr = 0
		p.Dat = nil
	}
	m.Dat = append(m.Dat, w.Bytes()...)
	return
}

func (p *Packet) Decrypt(t *tea.TEA) error {
	d := t.Decrypt(p.Dat)
	m := md5.Sum(d)
	if m != p.md5 {
		return errors.New("md5 mismatch")
	}
	p.Dat = d
	return nil
}

func (p *Packet) fillDat() {
	dat := (*slice)(unsafe.Pointer(&p.Dat))
	dat.data = unsafe.Pointer(&p.dat)
	dat.len = int(p.len)
	dat.cap = PKT_DATA_LEN
}

func (p *Packet) Read(b []byte) (n int, err error) {
	if p.ptr < 0 {
		p.ptr = 0
	}
	end := PKT_HEAD_LEN + int(p.len)
	if p.ptr >= int16(end) {
		err = io.EOF
		return
	}
	raw := (*[PKT_HEAD_LEN + PKT_DATA_LEN]byte)(unsafe.Pointer(p))
	buf := raw[p.ptr:end]
	n = copy(b, buf)
	p.ptr += int16(n)
	return
}

// ReadFrom unmarshals data from r into p
func (p *Packet) ReadFrom(r io.Reader) (n int64, err error) {
	if p.ptr < 0 {
		err = io.EOF
		return
	}
	raw := (*[PKT_HEAD_LEN + PKT_DATA_LEN]byte)(unsafe.Pointer(p))
	_, err = r.Read(raw[:1])
	if err != nil {
		return
	}
	end := PKT_HEAD_LEN + int(p.len)
	buf := raw[1:end]
	cnt, err := io.ReadFull(r, buf)
	n = int64(cnt)
	if err == nil {
		p.ptr = -1
		p.fillDat()
	}
	return
}

// Write unmarshals data b into p
func (p *Packet) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return
	}
	if p.ptr < 0 {
		err = io.EOF
		return
	}
	raw := (*[PKT_HEAD_LEN + PKT_DATA_LEN]byte)(unsafe.Pointer(p))
	if p.len == 0 { // first read
		p.len = b[0]
		end := PKT_HEAD_LEN + int(p.len)
		buf := raw[1:end]
		n = copy(buf, b[1:]) + 1
		if n == len(buf)+1 { // read complete
			p.ptr = -1
			p.fillDat()
			return
		}
		p.ptr = int16(n)
		return
	}
	buf := raw[int(p.ptr) : PKT_HEAD_LEN+int(p.len)]
	n = copy(buf, b)
	if n+int(p.ptr) == PKT_HEAD_LEN+int(p.len) {
		p.ptr = -1
		p.fillDat()
		return
	}
	p.ptr = int16(n)
	return
}

func (p *Packet) WriteTo(w io.Writer) (n int64, err error) {
	if p.ptr < 0 {
		p.ptr = 0
	}
	end := PKT_HEAD_LEN + int(p.len)
	if p.ptr >= int16(end) {
		err = io.EOF
		return
	}
	raw := (*[PKT_HEAD_LEN + PKT_DATA_LEN]byte)(unsafe.Pointer(p))
	buf := raw[p.ptr:end]
	cnt := 0
	for p.ptr < int16(end) {
		cnt, err = w.Write(buf)
		n += int64(cnt)
		if err != nil {
			return
		}
		p.ptr += int16(n)
		buf = buf[cnt:]
	}
	return
}
