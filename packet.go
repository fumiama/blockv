package blockv

import (
	"crypto/md5"
	"errors"
	"io"
	"unsafe"

	tea "github.com/fumiama/gofastTEA"
)

const (
	PKTTYP_GET = iota // get value (a block) by key
	PKTTYP_CAT        // catch all blocks
	PKTTYP_LST        // list all peers
	PKTTYP_SET        // set value (a block) of key
	PKTTYP_DEL        // del value (a block) of key
)

type Packet struct {
	len uint8     // len of dat
	typ uint8     // one of PKTTYP
	md5 [16]byte  // the dat's md5 before encrypt
	dat [256]byte // content depends on typ
	ptr int16     // progress of read/write
	Dat []byte    // an easy-to-use pointer of dat
	io.Reader
	io.ReaderFrom
	io.Writer
	io.WriterTo
}

func NewPacket(typ uint8, data []byte, t *tea.TEA) (p *Packet, err error) {
	lens := len(data)
	fill := 10 - (lens+1)%8
	total := fill + lens + 7
	if total > 255 {
		err = errors.New("data is too long")
		return
	}
	p = &Packet{
		len: uint8(total),
		typ: typ,
		md5: md5.Sum(data),
	}
	_ = t.EncryptTo(data, p.dat[:])
	return
}

func (p *Packet) fillDat() {
	dat := (*slice)(unsafe.Pointer(&p.Dat))
	dat.data = unsafe.Pointer(&p.dat)
	dat.len = int(p.len)
	dat.cap = 256
}

func (p *Packet) Read(b []byte) (n int, err error) {
	if p.ptr < 0 {
		p.ptr = 0
	}
	end := 1 + 1 + 16 + int(p.len)
	if p.ptr >= int16(end) {
		err = io.EOF
		return
	}
	raw := (*[1 + 1 + 16 + 256]byte)(unsafe.Pointer(p))
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
	raw := (*[1 + 1 + 16 + 256]byte)(unsafe.Pointer(p))
	_, err = r.Read(raw[:1])
	if err != nil {
		return
	}
	end := 1 + 1 + 16 + int(p.len)
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
	raw := (*[1 + 1 + 16 + 256]byte)(unsafe.Pointer(p))
	if p.len == 0 { // first read
		p.len = b[0]
		end := 1 + 1 + 16 + int(p.len)
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
	buf := raw[int(p.ptr) : 1+1+16+int(p.len)]
	n = copy(buf, b)
	if n+int(p.ptr) == 1+1+16+int(p.len) {
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
	end := 1 + 1 + 16 + int(p.len)
	if p.ptr >= int16(end) {
		err = io.EOF
		return
	}
	raw := (*[1 + 1 + 16 + 256]byte)(unsafe.Pointer(p))
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
