package blockv

import (
	"bytes"
	"crypto/md5"
	"errors"
	"io"
	"net"
	"unsafe"
)

// Block 区块链中的一块。
// 当有分支出现时，将选择
// md5值最小的区块进行链接
// 其余区块将被丢弃，直到
// 在新的链的末尾重新发起
// 链接请求，重复比较过程
type Block struct {
	pub [57]byte // signer of this block
	sln uint8    // signature len
	sgn [64]byte // signature of md5 digest of previous block's 255 bytes data + this block's 255 bytes data (this block's sgn is all zero in calc)
	dat []byte   // block contents
	pro []Protocol
}

func NewBlock(protos ...Protocol) (b *Block, err error) {
	if len(protos) == 0 {
		return
	}
	w := SelectWriter()
	defer w.put()
	for _, p := range protos {
		err = w.WriteByte(byte(p.Type()))
		if err != nil {
			return
		}
		_, err = io.Copy(w, p)
		if err != nil {
			return
		}
	}
	b = SelectBlock()
	b.dat = make([]byte, w.Len())
	copy(b.dat, w.Bytes())
	return
}

func ParseBlock(data []byte) (b *Block, err error) {
	if len(data) <= 57+1+64 {
		err = errors.New("data too short")
		return
	}
	b = SelectBlock()
	raw := (*[57 + 1 + 64]byte)(unsafe.Pointer(b))
	copy(raw[:], data)
	b.dat = data[57+1+64:]
	protosmu.RLock()
	defer protosmu.RUnlock()
	r := bytes.NewReader(data[57+1+64:])
	for r.Len() > 0 {
		typ, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		p, ok := prototypes[ProtoType(typ)]
		if !ok {
			return nil, errors.New("unknown protocol")
		}
		pro := p.New()
		_, err = io.Copy(pro, r)
		if err != nil {
			return nil, err
		}
		b.pro = append(b.pro, pro)
	}
	return
}

func (b *Block) Sign(me *Me, prev *Block) error {
	b.pub = me.pubk
	h := md5.New()
	if prev != nil {
		_, err := h.Write((*[57 + 64]byte)(unsafe.Pointer(prev))[:])
		if err != nil {
			return err
		}
		_, err = h.Write(prev.dat)
		if err != nil {
			return err
		}
	}
	_, err := h.Write(b.pub[:])
	if err != nil {
		return err
	}
	_, err = h.Write(make([]byte, 64))
	if err != nil {
		return err
	}
	_, err = h.Write(b.dat)
	if err != nil {
		return err
	}
	digest := h.Sum(nil)
	sgn, err := me.Sign(digest)
	if err != nil {
		return err
	}
	b.sln = uint8(len(sgn))
	copy(b.sgn[:], sgn)
	return nil
}

// Verify pass means digest *[16]byte != nil and err == nil
func (b *Block) Verify(prev *Block) (*[16]byte, error) {
	h := md5.New()
	if prev != nil {
		_, err := h.Write((*[57 + 64]byte)(unsafe.Pointer(prev))[:])
		if err != nil {
			return nil, err
		}
		_, err = h.Write(prev.dat)
		if err != nil {
			return nil, err
		}
	}
	_, err := h.Write(b.pub[:])
	if err != nil {
		return nil, err
	}
	_, err = h.Write(make([]byte, 64))
	if err != nil {
		return nil, err
	}
	_, err = h.Write(b.dat)
	if err != nil {
		return nil, err
	}
	digest := h.Sum(nil)
	if Verify(b.pub[:], digest, b.sgn[:b.sln]) {
		return (*[16]byte)((*slice)(unsafe.Pointer(&digest)).data), nil
	}
	return nil, errors.New("verification failed")
}

// Buffer is used to marshal block into bytes
func (b *Block) Buffer() (buf net.Buffers) {
	buf = make(net.Buffers, 2)
	buf[0] = *(*[]byte)(unsafe.Pointer(&slice{
		data: unsafe.Pointer(b),
		len:  57 + 1 + 64,
		cap:  57 + 1 + 64,
	}))
	buf[1] = b.dat
	return
}
